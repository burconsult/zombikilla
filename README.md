# zombikilla

Zombie process killer for Mac OS devs.

## Overview

`zombikilla` is a macOS status bar utility built with Rust that watches common development ports and lets you quickly terminate stray processes that keep your ports busy. The tool updates every two seconds, shows the number of detected listeners directly in the status bar, and exposes a dynamic tray menu so you can kill individual processes or clean everything up at once.

## Features

- Watches configurable ports or ranges using `lsof -ti :PORT -sTCP:LISTEN`.
- Displays the total process count in the menu bar (`0` when clear or `N⚠️` when listeners are found).
- Real-time tooltip updates describing detected processes.
- Dynamic tray menu entries for each active process and quick "Kill All" support.
- Graceful (`SIGTERM`) then forceful (`SIGKILL`) termination with permission-aware error handling.
- Multi-threaded architecture powered by `winit`, `tray-icon`, `nix`, and `crossbeam-channel`.

## Configuration

Copy `config.sample.toml` to `config.toml` and adjust the `ports` array to match your local development habits. Each entry may be a single port (`"3000"`) or a range (`"3000-3010"`). The optional `poll_interval_secs` controls how frequently the ports are scanned (defaults to 2 seconds).

```toml
ports = [
  "3000-3010",
  "8080",
  "5173"
]
poll_interval_secs = 2
```

Place `config.toml` either next to the compiled binary or in the working directory you launch `zombikilla` from.

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/yourusername/zombikilla.git
cd zombikilla

# Build the release binary
cargo build --release

# The binary will be at: target/release/zombikilla_app
```

### Running

```bash
# Run directly from target
./target/release/zombikilla_app

# Or copy to a location in your PATH
cp target/release/zombikilla_app /usr/local/bin/zombikilla
zombikilla
```

The application is a menu bar–only tool, so launching it will not open any windows. Look for the icon in your macOS menu bar (shows `0` when no processes are detected, or `N⚠️` when processes are found).

## Usage

1. **Launch the app** - The icon appears in your menu bar
2. **Click the icon** - View all detected processes listening on monitored ports
3. **Kill individual processes** - Click a specific process entry
4. **Kill all processes** - Click "Kill All Processes" to terminate all detected listeners

The app attempts graceful termination (SIGTERM) first, waiting up to 3 seconds. If the process doesn't exit, it forces termination with SIGKILL.

## Development

### Running Tests

```bash
cargo test
```

### Code Quality

```bash
# Format code
cargo fmt

# Run linter
cargo clippy

# Run all checks
cargo fmt --all -- --check && cargo clippy -- -D warnings && cargo test
```
