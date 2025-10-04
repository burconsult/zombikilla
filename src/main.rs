//! # zombikilla
//!
//! A macOS status bar utility that monitors development ports and helps terminate
//! stray processes that keep your ports busy.
//!
//! ## Architecture
//!
//! The application uses a multi-threaded architecture:
//! - **Scanner Thread**: Periodically scans configured ports using `lsof`
//! - **Killer Thread**: Handles process termination requests (SIGTERM then SIGKILL)
//! - **Menu Listener Thread**: Listens for menu item clicks from the system tray
//! - **Main Event Loop**: Manages the tray icon and coordinates between threads
//!
//! ## Configuration
//!
//! The app looks for `config.toml` in:
//! 1. Current working directory
//! 2. Directory containing the executable
//!
//! If no config is found, it uses sensible defaults for common development ports.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};
use log::{info, warn};
use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Deserialize;
use thiserror::Error;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItem, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};
use winit::event::{Event, StartCause};
use winit::event_loop::{EventLoop, EventLoopBuilder, EventLoopWindowTarget};

const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;
const DEFAULT_PORT_SPECS: &[&str] = &[
    "3000-3010",
    "4200",
    "5000",
    "5173",
    "7000-7010",
    "8000",
    "8080",
    "9000",
];

#[derive(Debug, Clone, Deserialize)]
struct Config {
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    poll_interval_secs: Option<u64>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ports: DEFAULT_PORT_SPECS.iter().map(|s| s.to_string()).collect(),
            poll_interval_secs: Some(DEFAULT_POLL_INTERVAL_SECS),
        }
    }
}

impl Config {
    fn load() -> Result<Self> {
        let mut candidates: Vec<PathBuf> = Vec::new();
        if let Ok(current_dir) = std::env::current_dir() {
            candidates.push(current_dir.join("config.toml"));
        }
        if let Ok(exe_path) = std::env::current_exe() {
            if let Some(dir) = exe_path.parent() {
                candidates.push(dir.join("config.toml"));
            }
        }

        for path in candidates {
            if path.exists() {
                let contents = fs::read_to_string(&path).with_context(|| {
                    format!("Failed to read configuration from {}", path.display())
                })?;
                let config: Config = toml::from_str(&contents).with_context(|| {
                    format!("Failed to parse configuration at {}", path.display())
                })?;
                info!("Loaded configuration from {}", path.display());
                return Ok(config);
            }
        }

        Ok(Config::default())
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(
            self.poll_interval_secs
                .unwrap_or(DEFAULT_POLL_INTERVAL_SECS),
        )
    }

    fn resolved_ports(&self) -> Vec<u16> {
        let mut ports = Vec::new();
        for entry in &self.ports {
            match parse_port_entry(entry) {
                Ok(mut values) => ports.append(&mut values),
                Err(err) => warn!("{}", err),
            }
        }
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

/// Parses a port specification string into a list of port numbers.
///
/// Supports both single ports ("8080") and ranges ("3000-3010").
///
/// # Examples
///
/// ```
/// # use zombikilla_app::parse_port_entry;
/// let ports = parse_port_entry("8080").unwrap();
/// assert_eq!(ports, vec![8080]);
///
/// let range = parse_port_entry("3000-3002").unwrap();
/// assert_eq!(range, vec![3000, 3001, 3002]);
/// ```
fn parse_port_entry(entry: &str) -> Result<Vec<u16>> {
    let trimmed = entry.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    if let Some((start, end)) = trimmed.split_once('-') {
        let start_port: u16 = start
            .trim()
            .parse()
            .with_context(|| format!("Invalid start port '{}' in range '{}'", start, entry))?;
        let end_port: u16 = end
            .trim()
            .parse()
            .with_context(|| format!("Invalid end port '{}' in range '{}'", end, entry))?;
        if start_port > end_port {
            anyhow::bail!("Invalid port range '{}': start must be <= end", entry);
        }
        Ok((start_port..=end_port).collect())
    } else {
        let port: u16 = trimmed
            .parse()
            .with_context(|| format!("Invalid port specification '{}'", entry))?;
        Ok(vec![port])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ProcessKey {
    port: u16,
    pid: i32,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    port: u16,
    pid: i32,
    command: String,
}

#[derive(Debug, Clone)]
struct ProcessSnapshot {
    processes: Vec<ProcessInfo>,
}

#[derive(Debug, Clone)]
enum AppEvent {
    ProcessUpdate(ProcessSnapshot),
    StatusMessage(String),
    MenuSelected(MenuId),
    #[allow(dead_code)]
    Exit,
}

#[derive(Debug, Clone)]
enum KillCommand {
    KillProcess(ProcessInfo),
    KillAll(Vec<ProcessInfo>),
}

struct AppState {
    tray_icon: Option<TrayIcon>,
    menu: Option<Menu>,
    kill_all_id: MenuId,
    quit_id: MenuId,
    process_items: HashMap<MenuId, ProcessInfo>,
    processes: Vec<ProcessInfo>,
    last_status_message: Option<String>,
    kill_tx: Sender<KillCommand>,
    event_rx: Receiver<AppEvent>,
    should_exit: bool,
}

impl AppState {
    fn new(
        kill_all_id: MenuId,
        quit_id: MenuId,
        kill_tx: Sender<KillCommand>,
        event_rx: Receiver<AppEvent>,
    ) -> Self {
        AppState {
            tray_icon: None,
            menu: None,
            kill_all_id,
            quit_id,
            process_items: HashMap::new(),
            processes: Vec::new(),
            last_status_message: None,
            kill_tx,
            event_rx,
            should_exit: false,
        }
    }

    fn initialize_tray(&mut self) -> Result<()> {
        let menu = Menu::new();
        let kill_all_item =
            MenuItem::with_id(self.kill_all_id.clone(), "Kill All Processes", false, None);
        menu.append(&kill_all_item)?;
        menu.append(&PredefinedMenuItem::separator())?;
        let quit_item = MenuItem::with_id(self.quit_id.clone(), "Quit", true, None);
        menu.append(&quit_item)?;

        let tray_icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu.clone()))
            .with_title("0")
            .with_tooltip("No listening dev servers detected.")
            .build()
            .context("Failed to create tray icon")?;

        self.tray_icon = Some(tray_icon);
        self.menu = Some(menu);
        Ok(())
    }

    fn update_processes(&mut self, processes: Vec<ProcessInfo>) -> Result<()> {
        self.processes = processes;
        self.rebuild_menu()?;
        self.refresh_icon_text()
    }

    fn set_status_message(&mut self, message: Option<String>) -> Result<()> {
        self.last_status_message = message;
        self.refresh_tooltip()
    }

    fn refresh_icon_text(&mut self) -> Result<()> {
        let count = self.processes.len();
        let title = if count == 0 {
            "0".to_string()
        } else {
            format!("{}⚠️", count)
        };
        if let Some(tray_icon) = &mut self.tray_icon {
            tray_icon.set_title(Some(title));
        }
        self.refresh_tooltip()
    }

    fn refresh_tooltip(&mut self) -> Result<()> {
        let mut lines: Vec<String> = Vec::new();
        if let Some(message) = &self.last_status_message {
            lines.push(message.clone());
        }
        if self.processes.is_empty() {
            lines.push("No listening dev servers detected.".into());
        } else {
            lines.push("Active listeners:".into());
            for process in &self.processes {
                lines.push(format!(
                    "Port {}: {} (PID {})",
                    process.port, process.command, process.pid
                ));
            }
        }
        let tooltip = lines.join("\n");
        if let Some(tray_icon) = &mut self.tray_icon {
            let _ = tray_icon.set_tooltip(Some(tooltip));
        }
        Ok(())
    }

    fn rebuild_menu(&mut self) -> Result<()> {
        let new_menu = Menu::new();
        let has_processes = !self.processes.is_empty();

        let kill_all_item = MenuItem::with_id(
            self.kill_all_id.clone(),
            "Kill All Processes",
            has_processes,
            None,
        );
        new_menu.append(&kill_all_item)?;
        new_menu.append(&PredefinedMenuItem::separator())?;

        self.process_items.clear();
        for process in &self.processes {
            let id = MenuId::new(format!("process_{}", process.pid));
            let label = format!(
                "Kill: Port {}: {} (PID {})",
                process.port, process.command, process.pid
            );
            let item = MenuItem::with_id(id.clone(), label, true, None);
            new_menu.append(&item)?;
            self.process_items.insert(id, process.clone());
        }

        if has_processes {
            new_menu.append(&PredefinedMenuItem::separator())?;
        }

        let quit_item = MenuItem::with_id(self.quit_id.clone(), "Quit", true, None);
        new_menu.append(&quit_item)?;

        if let Some(tray_icon) = &mut self.tray_icon {
            tray_icon.set_menu(Some(Box::new(new_menu.clone())));
        }
        self.menu = Some(new_menu);
        self.refresh_tooltip()?;
        Ok(())
    }

    fn take_process_for_id(&self, id: &MenuId) -> Option<ProcessInfo> {
        self.process_items.get(id).cloned()
    }

    fn handle_menu_event(&mut self, id: MenuId) -> Result<()> {
        if id == self.quit_id {
            info!("Quit selected");
            self.should_exit = true;
        } else if id == self.kill_all_id {
            if !self.processes.is_empty() {
                let _ = self
                    .kill_tx
                    .send(KillCommand::KillAll(self.processes.clone()));
                self.set_status_message(Some("Killing all tracked processes".into()))?;
            }
        } else if let Some(process) = self.take_process_for_id(&id) {
            let _ = self.kill_tx.send(KillCommand::KillProcess(process.clone()));
            self.set_status_message(Some(format!(
                "Sent termination signal to PID {} on port {}",
                process.pid, process.port
            )))?;
        }
        Ok(())
    }

    fn process_events(&mut self) -> Result<()> {
        while let Ok(event) = self.event_rx.try_recv() {
            match event {
                AppEvent::ProcessUpdate(snapshot) => {
                    self.update_processes(snapshot.processes)?;
                }
                AppEvent::StatusMessage(message) => {
                    self.set_status_message(Some(message))?;
                }
                AppEvent::MenuSelected(id) => {
                    self.handle_menu_event(id)?;
                }
                AppEvent::Exit => {
                    self.should_exit = true;
                }
            }
        }
        Ok(())
    }
}

impl AppState {
    fn handle_event(&mut self, event: Event<AppEvent>, elwt: &EventLoopWindowTarget<AppEvent>) {
        match event {
            Event::NewEvents(StartCause::Init) => {
                if let Err(e) = self.initialize_tray() {
                    warn!("Failed to initialize tray icon: {}", e);
                    self.should_exit = true;
                } else {
                    info!("Tray icon initialized successfully");
                }
            }
            Event::UserEvent(app_event) => match app_event {
                AppEvent::ProcessUpdate(snapshot) => {
                    if let Err(e) = self.update_processes(snapshot.processes) {
                        warn!("Failed to update processes: {}", e);
                    }
                }
                AppEvent::StatusMessage(message) => {
                    if let Err(e) = self.set_status_message(Some(message)) {
                        warn!("Failed to set status message: {}", e);
                    }
                }
                AppEvent::MenuSelected(id) => {
                    if let Err(e) = self.handle_menu_event(id) {
                        warn!("Failed to handle menu event: {}", e);
                    }
                }
                AppEvent::Exit => {
                    self.should_exit = true;
                }
            },
            Event::AboutToWait => {
                if let Err(e) = self.process_events() {
                    warn!("Error processing events: {}", e);
                }
            }
            _ => {}
        }

        if self.should_exit {
            elwt.exit();
        }
    }
}

#[derive(Debug, Error)]
enum KillError {
    #[error("Permission denied when signaling PID {pid}")]
    PermissionDenied { pid: i32 },
    #[error("Failed to signal PID {pid}: {source}")]
    SignalFailure {
        pid: i32,
        #[source]
        source: Errno,
    },
}

#[derive(Debug)]
enum TerminationResult {
    AlreadyExited,
    Graceful,
    Forced,
}

fn main() -> Result<()> {
    env_logger::init();

    let config = Config::load()?;
    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event().build()?;
    let proxy = event_loop.create_proxy();

    let kill_all_id = MenuId::new("kill_all");
    let quit_id = MenuId::new("quit");

    let (kill_tx, kill_rx) = unbounded::<KillCommand>();
    let (event_tx, event_rx) = unbounded::<AppEvent>();

    spawn_scanner_thread(config.clone(), proxy.clone(), event_tx.clone());
    spawn_killer_thread(kill_rx, proxy.clone(), event_tx.clone());
    spawn_menu_listener(proxy.clone(), event_tx);

    let mut app_state = AppState::new(kill_all_id, quit_id, kill_tx, event_rx);

    event_loop.run(move |event, elwt| {
        app_state.handle_event(event, elwt);
    })?;

    info!("Application exited cleanly");
    Ok(())
}

fn spawn_scanner_thread(
    config: Config,
    proxy: winit::event_loop::EventLoopProxy<AppEvent>,
    event_tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        let ports = config.resolved_ports();
        if ports.is_empty() {
            warn!("No ports configured for monitoring");
        }
        let interval = config.poll_interval();
        loop {
            let snapshot = scan_ports(&ports);
            if proxy
                .send_event(AppEvent::ProcessUpdate(snapshot.clone()))
                .is_err()
            {
                break;
            }
            if event_tx.send(AppEvent::ProcessUpdate(snapshot)).is_err() {
                break;
            }
            thread::sleep(interval);
        }
    });
}

fn spawn_killer_thread(
    kill_rx: Receiver<KillCommand>,
    proxy: winit::event_loop::EventLoopProxy<AppEvent>,
    event_tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        while let Ok(command) = kill_rx.recv() {
            match command {
                KillCommand::KillProcess(process) => match terminate_process(process.pid) {
                    Ok(result) => {
                        let message = match result {
                            TerminationResult::AlreadyExited => {
                                format!("Process PID {} was already stopped.", process.pid)
                            }
                            TerminationResult::Graceful => format!(
                                "Gracefully terminated PID {} (port {}).",
                                process.pid, process.port
                            ),
                            TerminationResult::Forced => {
                                format!("Force killed PID {} (port {}).", process.pid, process.port)
                            }
                        };
                        let _ = proxy.send_event(AppEvent::StatusMessage(message.clone()));
                        let _ = event_tx.send(AppEvent::StatusMessage(message));
                    }
                    Err(err) => {
                        warn!("Failed to kill PID {}: {}", process.pid, err);
                        let message = format!("Unable to terminate PID {}: {}", process.pid, err);
                        let _ = proxy.send_event(AppEvent::StatusMessage(message.clone()));
                        let _ = event_tx.send(AppEvent::StatusMessage(message));
                    }
                },
                KillCommand::KillAll(processes) => {
                    for process in processes {
                        match terminate_process(process.pid) {
                            Ok(result) => {
                                let message = match result {
                                    TerminationResult::AlreadyExited => {
                                        format!("Process PID {} was already stopped.", process.pid)
                                    }
                                    TerminationResult::Graceful => format!(
                                        "Gracefully terminated PID {} (port {}).",
                                        process.pid, process.port
                                    ),
                                    TerminationResult::Forced => format!(
                                        "Force killed PID {} (port {}).",
                                        process.pid, process.port
                                    ),
                                };
                                let _ = proxy.send_event(AppEvent::StatusMessage(message.clone()));
                                let _ = event_tx.send(AppEvent::StatusMessage(message));
                            }
                            Err(err) => {
                                warn!("Failed to kill PID {}: {}", process.pid, err);
                                let message =
                                    format!("Unable to terminate PID {}: {}", process.pid, err);
                                let _ = proxy.send_event(AppEvent::StatusMessage(message.clone()));
                                let _ = event_tx.send(AppEvent::StatusMessage(message));
                            }
                        }
                    }
                }
            }
        }
    });
}

fn spawn_menu_listener(
    proxy: winit::event_loop::EventLoopProxy<AppEvent>,
    event_tx: Sender<AppEvent>,
) {
    thread::spawn(move || {
        let receiver = MenuEvent::receiver();
        while let Ok(event) = receiver.recv() {
            if proxy
                .send_event(AppEvent::MenuSelected(event.id.clone()))
                .is_err()
            {
                break;
            }
            if event_tx
                .send(AppEvent::MenuSelected(event.id.clone()))
                .is_err()
            {
                break;
            }
        }
    });
}

fn scan_ports(ports: &[u16]) -> ProcessSnapshot {
    let mut processes: HashMap<ProcessKey, ProcessInfo> = HashMap::new();
    for &port in ports {
        match scan_port(port) {
            Ok(found) => {
                for process in found {
                    processes.insert(
                        ProcessKey {
                            port: process.port,
                            pid: process.pid,
                        },
                        process,
                    );
                }
            }
            Err(err) => {
                warn!("Failed to scan port {}: {}", port, err);
            }
        }
    }

    let mut processes: Vec<ProcessInfo> = processes.into_values().collect();
    processes.sort_by(|a, b| a.port.cmp(&b.port).then_with(|| a.pid.cmp(&b.pid)));
    ProcessSnapshot { processes }
}

/// Scans a specific port for listening processes using `lsof`.
///
/// Executes `lsof -ti :PORT -sTCP:LISTEN` to find PIDs, then queries
/// each process name using `ps`.
///
/// # Arguments
///
/// * `port` - The port number to scan
///
/// # Returns
///
/// A vector of `ProcessInfo` for all processes listening on the port.
/// Returns an empty vector if no processes are found (lsof exit code 1).
fn scan_port(port: u16) -> Result<Vec<ProcessInfo>> {
    let output = Command::new("lsof")
        .args(["-ti", &format!(":{}", port), "-sTCP:LISTEN"])
        .output()
        .with_context(|| format!("Failed to execute lsof for port {}", port))?;

    if !output.status.success() {
        if output.status.code() == Some(1) {
            return Ok(Vec::new());
        }
        anyhow::bail!(
            "lsof returned error code {:?} for port {}",
            output.status.code(),
            port
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let pid: i32 = trimmed
            .parse()
            .with_context(|| format!("Unable to parse PID '{}' from lsof output", trimmed))?;
        let command = query_process_command(pid).unwrap_or_else(|| "unknown".into());
        processes.push(ProcessInfo { port, pid, command });
    }
    Ok(processes)
}

fn query_process_command(pid: i32) -> Option<String> {
    let output = Command::new("ps")
        .args(["-p", &pid.to_string(), "-o", "comm="])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let command = stdout.trim();
    if command.is_empty() {
        None
    } else {
        Some(command.to_string())
    }
}

/// Attempts to terminate a process, first gracefully (SIGTERM) then forcefully (SIGKILL).
///
/// The function first sends SIGTERM and waits up to 3 seconds for the process to exit.
/// If the process doesn't exit within this time, it sends SIGKILL.
///
/// # Arguments
///
/// * `pid` - The process ID to terminate
///
/// # Returns
///
/// * `Ok(TerminationResult::AlreadyExited)` - Process was already dead
/// * `Ok(TerminationResult::Graceful)` - Process exited after SIGTERM
/// * `Ok(TerminationResult::Forced)` - Process was killed with SIGKILL
/// * `Err(KillError::PermissionDenied)` - Insufficient permissions
/// * `Err(KillError::SignalFailure)` - Other signal error
fn terminate_process(pid: i32) -> Result<TerminationResult, KillError> {
    let nix_pid = Pid::from_raw(pid);
    match kill(nix_pid, Some(Signal::SIGTERM)) {
        Ok(_) => {}
        Err(Errno::ESRCH) => return Ok(TerminationResult::AlreadyExited),
        Err(Errno::EPERM) => {
            return Err(KillError::PermissionDenied { pid });
        }
        Err(err) => {
            return Err(KillError::SignalFailure { pid, source: err });
        }
    }

    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match kill(nix_pid, None) {
            Ok(_) => {
                if Instant::now() >= deadline {
                    break;
                }
            }
            Err(Errno::ESRCH) => {
                return Ok(TerminationResult::Graceful);
            }
            Err(Errno::EPERM) => {
                return Err(KillError::PermissionDenied { pid });
            }
            Err(err) => {
                return Err(KillError::SignalFailure { pid, source: err });
            }
        }
        thread::sleep(Duration::from_millis(200));
    }

    match kill(nix_pid, Some(Signal::SIGKILL)) {
        Ok(_) => Ok(TerminationResult::Forced),
        Err(Errno::ESRCH) => Ok(TerminationResult::Graceful),
        Err(Errno::EPERM) => Err(KillError::PermissionDenied { pid }),
        Err(err) => Err(KillError::SignalFailure { pid, source: err }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_port_entry_single() {
        let result = parse_port_entry("8080").unwrap();
        assert_eq!(result, vec![8080]);
    }

    #[test]
    fn test_parse_port_entry_range() {
        let result = parse_port_entry("3000-3002").unwrap();
        assert_eq!(result, vec![3000, 3001, 3002]);
    }

    #[test]
    fn test_parse_port_entry_invalid_range() {
        let result = parse_port_entry("5000-4000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_entry_invalid_port() {
        let result = parse_port_entry("not_a_port");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_port_entry_empty() {
        let result = parse_port_entry("").unwrap();
        assert_eq!(result, Vec::<u16>::new());
    }

    #[test]
    fn test_config_resolved_ports_deduplication() {
        let config = Config {
            ports: vec![
                "3000".to_string(),
                "3000-3002".to_string(),
                "3001".to_string(),
            ],
            poll_interval_secs: Some(2),
        };
        let ports = config.resolved_ports();
        assert_eq!(ports, vec![3000, 3001, 3002]);
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(!config.ports.is_empty());
        assert_eq!(config.poll_interval_secs, Some(DEFAULT_POLL_INTERVAL_SECS));
    }

    #[test]
    fn test_config_poll_interval() {
        let config = Config {
            ports: vec![],
            poll_interval_secs: Some(5),
        };
        assert_eq!(config.poll_interval(), Duration::from_secs(5));
    }

    #[test]
    fn test_config_poll_interval_default() {
        let config = Config {
            ports: vec![],
            poll_interval_secs: None,
        };
        assert_eq!(
            config.poll_interval(),
            Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS)
        );
    }
}
