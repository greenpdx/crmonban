//! Display server subprocess management
//!
//! Spawns and manages the crmonban-display server as a subprocess.

use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::{Child, Command};
use tracing::{error, info, warn};

/// Display server subprocess manager
pub struct DisplayProcess {
    /// Path to the display binary
    binary_path: PathBuf,
    /// Socket path for IPC
    socket_path: PathBuf,
    /// Database path
    db_path: PathBuf,
    /// HTTP port for the dashboard
    http_port: u16,
    /// Child process handle
    child: Option<Child>,
}

impl DisplayProcess {
    /// Create a new display process manager
    pub fn new(
        binary_path: PathBuf,
        socket_path: PathBuf,
        db_path: PathBuf,
        http_port: u16,
    ) -> Self {
        Self {
            binary_path,
            socket_path,
            db_path,
            http_port,
            child: None,
        }
    }

    /// Find the display binary in common locations
    pub fn find_binary() -> Option<PathBuf> {
        let candidates = [
            // Same directory as main binary
            std::env::current_exe()
                .ok()
                .and_then(|p| p.parent().map(|d| d.join("crmonban-display"))),
            // System paths
            Some(PathBuf::from("/usr/bin/crmonban-display")),
            Some(PathBuf::from("/usr/local/bin/crmonban-display")),
            // Development paths
            Some(PathBuf::from("./target/release/crmonban-display")),
            Some(PathBuf::from("./display/backend/target/release/crmonban-display")),
        ];

        for candidate in candidates.into_iter().flatten() {
            if candidate.exists() {
                return Some(candidate);
            }
        }

        None
    }

    /// Spawn the display server
    pub async fn spawn(&mut self) -> anyhow::Result<()> {
        if self.child.is_some() {
            return Err(anyhow::anyhow!("Display server already running"));
        }

        if !self.binary_path.exists() {
            return Err(anyhow::anyhow!(
                "Display binary not found: {:?}",
                self.binary_path
            ));
        }

        info!("Spawning display server: {:?}", self.binary_path);

        let child = Command::new(&self.binary_path)
            .env("CRMONBAN_SOCKET", &self.socket_path)
            .env("CRMONBAN_DB", &self.db_path)
            .env("CRMONBAN_PORT", self.http_port.to_string())
            .env("RUST_LOG", "info")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?;

        let pid = child.id().unwrap_or(0);
        info!("Display server started with PID {}", pid);

        self.child = Some(child);
        Ok(())
    }

    /// Check if the display server is running
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(Some(status)) => {
                    warn!("Display server exited with status: {}", status);
                    self.child = None;
                    false
                }
                Ok(None) => true,
                Err(e) => {
                    error!("Failed to check display server status: {}", e);
                    false
                }
            }
        } else {
            false
        }
    }

    /// Stop the display server
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(ref mut child) = self.child {
            info!("Stopping display server");

            // Try graceful shutdown first (SIGTERM)
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                if let Some(pid) = child.id() {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
            }

            // Wait for graceful shutdown with timeout
            let timeout = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                child.wait(),
            )
            .await;

            match timeout {
                Ok(Ok(status)) => {
                    info!("Display server stopped: {}", status);
                }
                Ok(Err(e)) => {
                    warn!("Error waiting for display server: {}", e);
                }
                Err(_) => {
                    // Timeout - force kill
                    warn!("Display server did not stop gracefully, killing");
                    child.kill().await?;
                }
            }

            self.child = None;
        }

        Ok(())
    }

    /// Restart the display server
    pub async fn restart(&mut self) -> anyhow::Result<()> {
        self.stop().await?;
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        self.spawn().await
    }

    /// Get the display server PID
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().and_then(|c| c.id())
    }
}

impl Drop for DisplayProcess {
    fn drop(&mut self) {
        // Try to kill the child synchronously
        if let Some(ref mut child) = self.child {
            #[cfg(unix)]
            {
                use nix::sys::signal::{kill, Signal};
                use nix::unistd::Pid;

                if let Some(pid) = child.id() {
                    let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_binary() {
        // Just test that it doesn't panic
        let _result = DisplayProcess::find_binary();
    }
}
