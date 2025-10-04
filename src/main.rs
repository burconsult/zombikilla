use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use crossbeam_channel::{unbounded, Receiver};
use log::{info, warn};
use nix::errno::Errno;
use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use serde::Deserialize;
use thiserror::Error;
use tray_icon::menu::{Menu, MenuEvent, MenuId, MenuItemAttributes, PredefinedMenuItem};
use tray_icon::{TrayIcon, TrayIconBuilder};
use winit::event::{Event, StartCause};
use winit::event_loop::{ControlFlow, EventLoop, EventLoopBuilder, EventLoopProxy};

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
                let contents = fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read configuration from {}", path.display()))?;
                let config: Config = toml::from_str(&contents)
                    .with_context(|| format!("Failed to parse configuration at {}", path.display()))?;
                info!("Loaded configuration from {}", path.display());
                return Ok(config);
            }
        }

        Ok(Config::default())
    }

    fn poll_interval(&self) -> Duration {
        Duration::from_secs(self.poll_interval_secs.unwrap_or(DEFAULT_POLL_INTERVAL_SECS))
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
    Exit,
}

#[derive(Debug, Clone)]
enum KillCommand {
    KillProcess(ProcessInfo),
    KillAll(Vec<ProcessInfo>),
}

#[derive(Debug)]
struct AppState {
    tray_icon: TrayIcon,
    menu: Menu,
    kill_all_id: MenuId,
    quit_id: MenuId,
    process_items: HashMap<MenuId, ProcessInfo>,
    processes: Vec<ProcessInfo>,
    last_status_message: Option<String>,
}

impl AppState {
    fn new(mut tray_icon: TrayIcon, mut menu: Menu, kill_all_id: MenuId, quit_id: MenuId) -> Self {
        tray_icon.set_title(Some("0".to_string()));
        tray_icon.set_tooltip(Some("No listening dev servers detected.".into()));
        menu.add_item(MenuItemAttributes::new("Kill All Processes").with_id(kill_all_id.clone()).with_enabled(false));
        menu.add_native_item(PredefinedMenuItem::separator());
        menu.add_item(MenuItemAttributes::new("Quit").with_id(quit_id.clone()));
        AppState {
            tray_icon,
            menu,
            kill_all_id,
            quit_id,
            process_items: HashMap::new(),
            processes: Vec::new(),
            last_status_message: None,
        }
    }

    fn update_processes(&mut self, processes: Vec<ProcessInfo>) {
        self.processes = processes;
        self.rebuild_menu();
        self.refresh_icon_text();
    }

    fn set_status_message(&mut self, message: Option<String>) {
        self.last_status_message = message;
        self.refresh_tooltip();
    }

    fn refresh_icon_text(&mut self) {
        let count = self.processes.len();
        let title = if count == 0 {
            "0".to_string()
        } else {
            format!("{}⚠️", count)
        };
        let _ = self.tray_icon.set_title(Some(title));
        self.refresh_tooltip();
    }

    fn refresh_tooltip(&mut self) {
        let mut lines: Vec<String> = Vec::new();
        if let Some(message) = &self.last_status_message {
            lines.push(message.clone());
        }
        if self.processes.is_empty() {
            lines.push("No listening dev servers detected.".into());
        } else {
            lines.push("Active listeners:".into());
            for process in &self.processes {
                lines.push(format!("Port {}: {} (PID {})", process.port, process.command, process.pid));
            }
        }
        let tooltip = lines.join("\n");
        let _ = self.tray_icon.set_tooltip(Some(tooltip));
    }

    fn rebuild_menu(&mut self) {
        let mut new_menu = Menu::new();
        let has_processes = !self.processes.is_empty();
        new_menu.add_item(
            MenuItemAttributes::new("Kill All Processes")
                .with_id(self.kill_all_id.clone())
                .with_enabled(has_processes),
        );
        new_menu.add_native_item(PredefinedMenuItem::separator());

        self.process_items.clear();
        for process in &self.processes {
            let id = MenuId::new(format!("process_{}", process.pid));
            let label = format!("Kill: Port {}: {} (PID {})", process.port, process.command, process.pid);
            new_menu.add_item(MenuItemAttributes::new(label).with_id(id.clone()));
            self.process_items.insert(id, process.clone());
        }

        if has_processes {
            new_menu.add_native_item(PredefinedMenuItem::separator());
        }

        new_menu.add_item(MenuItemAttributes::new("Quit").with_id(self.quit_id.clone()));
        self.menu = new_menu.clone();
        let _ = self.tray_icon.set_menu(Some(new_menu));
        self.refresh_tooltip();
    }

    fn take_process_for_id(&self, id: &MenuId) -> Option<ProcessInfo> {
        self.process_items.get(id).cloned()
    }
}

#[derive(Debug, Error)]
enum KillError {
    #[error("Permission denied when signaling PID {pid}")]
    PermissionDenied { pid: i32 },
    #[error("Failed to signal PID {pid}: {source}")]
    SignalFailure { pid: i32, #[source] source: nix::Error },
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
    let event_loop: EventLoop<AppEvent> = EventLoopBuilder::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let kill_all_id = MenuId::new("kill_all".to_string());
    let quit_id = MenuId::new("quit".to_string());

    let menu = Menu::new();
    let tray_icon = TrayIconBuilder::new()
        .with_menu(menu.clone())
        .with_title("0")
        .with_tooltip("No listening dev servers detected.")
        .build()
        .context("Failed to create tray icon")?;

    let mut app_state = AppState::new(tray_icon, menu, kill_all_id.clone(), quit_id.clone());

    let (kill_tx, kill_rx) = unbounded::<KillCommand>();

    spawn_scanner_thread(config.clone(), proxy.clone());
    spawn_killer_thread(kill_rx, proxy.clone());
    spawn_menu_listener(proxy.clone());

    let kill_sender = kill_tx.clone();

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {
                info!("Starting zombikilla tray application");
            }
            Event::UserEvent(AppEvent::ProcessUpdate(snapshot)) => {
                app_state.update_processes(snapshot.processes);
            }
            Event::UserEvent(AppEvent::StatusMessage(message)) => {
                app_state.set_status_message(Some(message));
            }
            Event::UserEvent(AppEvent::MenuSelected(id)) => {
                if id == quit_id {
                    info!("Quit selected");
                    *control_flow = ControlFlow::Exit;
                } else if id == kill_all_id {
                    if !app_state.processes.is_empty() {
                        let _ = kill_sender.send(KillCommand::KillAll(app_state.processes.clone()));
                        app_state.set_status_message(Some("Killing all tracked processes".into()));
                    }
                } else if let Some(process) = app_state.take_process_for_id(&id) {
                    let _ = kill_sender.send(KillCommand::KillProcess(process.clone()));
                    app_state.set_status_message(Some(format!(
                        "Sent termination signal to PID {} on port {}",
                        process.pid, process.port
                    )));
                }
            }
            Event::UserEvent(AppEvent::Exit) => {
                *control_flow = ControlFlow::Exit;
            }
            Event::LoopDestroyed => {
                info!("Event loop destroyed");
            }
            _ => {}
        }
    });
}

fn spawn_scanner_thread(config: Config, proxy: EventLoopProxy<AppEvent>) {
    thread::spawn(move || {
        let ports = config.resolved_ports();
        if ports.is_empty() {
            warn!("No ports configured for monitoring");
        }
        let interval = config.poll_interval();
        loop {
            let snapshot = scan_ports(&ports);
            if proxy.send_event(AppEvent::ProcessUpdate(snapshot)).is_err() {
                break;
            }
            thread::sleep(interval);
        }
    });
}

fn spawn_killer_thread(kill_rx: Receiver<KillCommand>, proxy: EventLoopProxy<AppEvent>) {
    thread::spawn(move || {
        while let Ok(command) = kill_rx.recv() {
            match command {
                KillCommand::KillProcess(process) => match terminate_process(process.pid) {
                    Ok(result) => {
                        let message = match result {
                            TerminationResult::AlreadyExited => format!(
                                "Process PID {} was already stopped.",
                                process.pid
                            ),
                            TerminationResult::Graceful => format!(
                                "Gracefully terminated PID {} (port {}).",
                                process.pid, process.port
                            ),
                            TerminationResult::Forced => format!(
                                "Force killed PID {} (port {}).",
                                process.pid, process.port
                            ),
                        };
                        let _ = proxy.send_event(AppEvent::StatusMessage(message));
                    }
                    Err(err) => {
                        warn!("Failed to kill PID {}: {}", process.pid, err);
                        let _ = proxy.send_event(AppEvent::StatusMessage(format!(
                            "Unable to terminate PID {}: {}",
                            process.pid, err
                        )));
                    }
                },
                KillCommand::KillAll(processes) => {
                    for process in processes {
                        match terminate_process(process.pid) {
                            Ok(result) => {
                                let message = match result {
                                    TerminationResult::AlreadyExited => format!(
                                        "Process PID {} was already stopped.",
                                        process.pid
                                    ),
                                    TerminationResult::Graceful => format!(
                                        "Gracefully terminated PID {} (port {}).",
                                        process.pid, process.port
                                    ),
                                    TerminationResult::Forced => format!(
                                        "Force killed PID {} (port {}).",
                                        process.pid, process.port
                                    ),
                                };
                                let _ = proxy.send_event(AppEvent::StatusMessage(message));
                            }
                            Err(err) => {
                                warn!("Failed to kill PID {}: {}", process.pid, err);
                                let _ = proxy.send_event(AppEvent::StatusMessage(format!(
                                    "Unable to terminate PID {}: {}",
                                    process.pid, err
                                )));
                            }
                        }
                    }
                }
            }
        }
    });
}

fn spawn_menu_listener(proxy: EventLoopProxy<AppEvent>) {
    thread::spawn(move || {
        let receiver = MenuEvent::receiver();
        while let Ok(event) = receiver.recv() {
            if proxy.send_event(AppEvent::MenuSelected(event.id.clone())).is_err() {
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

fn terminate_process(pid: i32) -> Result<TerminationResult, KillError> {
    let nix_pid = Pid::from_raw(pid);
    match kill(nix_pid, Some(Signal::SIGTERM)) {
        Ok(_) => {}
        Err(nix::Error::Sys(Errno::ESRCH)) => return Ok(TerminationResult::AlreadyExited),
        Err(nix::Error::Sys(Errno::EPERM)) => {
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
            Err(nix::Error::Sys(Errno::ESRCH)) => {
                return Ok(TerminationResult::Graceful);
            }
            Err(nix::Error::Sys(Errno::EPERM)) => {
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
        Err(nix::Error::Sys(Errno::ESRCH)) => Ok(TerminationResult::Graceful),
        Err(nix::Error::Sys(Errno::EPERM)) => Err(KillError::PermissionDenied { pid }),
        Err(err) => Err(KillError::SignalFailure { pid, source: err }),
    }
}
