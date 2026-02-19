use mitmproxy::intercept_conf::{InterceptConf, load_config_document, set_startup_intercept_conf};
use notify::{RecursiveMode, Watcher};
use pyo3::exceptions::PyValueError;
use std::path::PathBuf;
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

#[cfg(target_os = "linux")]
use mitmproxy::packet_sources::linux::LinuxConf;
#[cfg(target_os = "macos")]
use mitmproxy::packet_sources::macos::MacosConf;
#[cfg(windows)]
use mitmproxy::packet_sources::windows::WindowsConf;

use pyo3::prelude::*;

use crate::server::base::Server;
use tokio::sync::mpsc;

#[pyclass(module = "mitmproxy_rs.local")]
#[derive(Debug)]
pub struct LocalRedirector {
    server: Server,
    conf_tx: mpsc::UnboundedSender<InterceptConf>,
    spec: String,
    watcher: Option<InterceptWatcher>,
}

#[derive(Debug)]
struct InterceptWatcher {
    stop_tx: std_mpsc::Sender<()>,
}

impl LocalRedirector {
    pub fn new(server: Server, conf_tx: mpsc::UnboundedSender<InterceptConf>) -> Self {
        Self {
            server,
            conf_tx,
            spec: "inactive".to_string(),
            watcher: None,
        }
    }
}

#[pymethods]
impl LocalRedirector {
    /// Return a textual description of the redirector interception spec,
    /// or raise a ValueError if the spec is invalid.
    ///
    /// This helper only describes explicit intercept specs passed to `set_intercept`.
    /// JSON-based policy files can also provide redirector exclusions.
    #[staticmethod]
    fn describe_spec(spec: &str) -> PyResult<String> {
        InterceptConf::try_from(spec)
            .map(|conf| conf.description())
            .map_err(|e| PyValueError::new_err(format!("{e:?}")))
    }

    /// Set a new redirector interception spec.
    ///
    /// This affects redirector flow selection immediately. The JSON policy loaded
    /// through MITMPROXY_NETWORK_POLICY_PATH can also update redirector exclusions.
    pub fn set_intercept(&mut self, spec: String) -> PyResult<()> {
        let conf = InterceptConf::try_from(spec.as_str())?;
        set_startup_intercept_conf(conf.clone());
        self.spec = spec;
        self.conf_tx
            .send(conf)
            .map_err(crate::util::event_queue_unavailable)?;
        if self.watcher.is_none() {
            self.watcher = start_intercept_watcher(self.conf_tx.clone());
        }
        Ok(())
    }

    /// Close the OS proxy server.
    pub fn close(&mut self) {
        self.server.close()
    }

    pub fn wait_closed<'p>(&self, py: Python<'p>) -> PyResult<Bound<'p, PyAny>> {
        self.server.wait_closed(py)
    }

    /// Returns a `str` describing why local redirect mode is unavailable, or `None` if it is available.
    ///
    /// Reasons for unavailability may be an unsupported platform, or missing privileges.
    #[staticmethod]
    pub fn unavailable_reason() -> Option<String> {
        #[cfg(any(windows, target_os = "macos"))]
        return None;

        #[cfg(target_os = "linux")]
        if nix::unistd::geteuid().is_root() {
            None
        } else {
            Some("mitmproxy is not running as root.".to_string())
        }

        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        Some(format!(
            "Local redirect mode is not supported on {}",
            std::env::consts::OS
        ))
    }

    pub fn __repr__(&self) -> String {
        format!("Local Redirector({})", self.spec)
    }
}

impl Drop for LocalRedirector {
    fn drop(&mut self) {
        if let Some(watcher) = self.watcher.take() {
            let _ = watcher.stop_tx.send(());
        }
    }
}

fn start_intercept_watcher(
    conf_tx: mpsc::UnboundedSender<InterceptConf>,
) -> Option<InterceptWatcher> {
    let path = std::env::var_os("MITMPROXY_NETWORK_POLICY_PATH").map(PathBuf::from)?;
    let (stop_tx, stop_rx) = std_mpsc::channel();

    std::thread::spawn(move || {
        let (event_tx, event_rx) = std_mpsc::channel();
        let mut watcher = match notify::recommended_watcher(move |res| {
            let _ = event_tx.send(res);
        }) {
            Ok(watcher) => watcher,
            Err(err) => {
                log::warn!("Failed to create file watcher: {err:?}");
                return;
            }
        };

        if let Err(err) = watcher.watch(&path, RecursiveMode::NonRecursive) {
            log::warn!("Failed to watch {}: {err:?}", path.display());
            return;
        }

        let mut last_spec: Option<String> = None;
        let mut reload = || {
            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(err) => {
                    log::warn!(
                        "Intercept watcher failed to read {}: {err:?}",
                        path.display()
                    );
                    return;
                }
            };
            let spec = content.trim().to_string();
            if last_spec.as_deref() == Some(&spec) {
                return;
            }
            match load_config_document(spec.as_str()) {
                Ok(conf) => {
                    if conf_tx.send(conf).is_err() {
                        log::warn!("Failed to dispatch intercept configuration update.");
                    }
                    last_spec = Some(spec);
                    log::info!("Network block policy watcher loaded {}", path.display());
                }
                Err(err) => {
                    log::warn!(
                        "Invalid network block policy in {}: {err:?}",
                        path.display()
                    );
                }
            }
        };

        reload();

        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match event_rx.recv_timeout(Duration::from_millis(250)) {
                Ok(Ok(_event)) => reload(),
                Ok(Err(err)) => {
                    log::debug!("Watch error for {}: {err:?}", path.display());
                }
                Err(std_mpsc::RecvTimeoutError::Timeout) => {}
                Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
    });

    Some(InterceptWatcher { stop_tx })
}

/// Start an OS-level proxy to intercept traffic from the current machine.
///
/// - `handle_tcp_stream`: An async function that will be called for each new TCP `Stream`.
/// - `handle_udp_stream`: An async function that will be called for each new UDP `Stream`.
///
/// *Availability: Windows, Linux, and macOS*
#[pyfunction]
#[allow(unused_variables)]
pub fn start_local_redirector(
    py: Python<'_>,
    handle_tcp_stream: PyObject,
    handle_udp_stream: PyObject,
) -> PyResult<Bound<'_, PyAny>> {
    #[cfg(windows)]
    {
        let executable_path: std::path::PathBuf = py
            .import("mitmproxy_windows")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = WindowsConf { executable_path };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(target_os = "linux")]
    {
        let executable_path: std::path::PathBuf = py
            .import("mitmproxy_linux")?
            .call_method0("executable_path")?
            .extract()?;
        if !executable_path.exists() {
            return Err(anyhow::anyhow!("{} does not exist", executable_path.display()).into());
        }
        let conf = LinuxConf { executable_path };
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;

            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(target_os = "macos")]
    {
        let module_filename = py.import("mitmproxy_macos")?.filename()?;
        let redirector_tar = std::path::Path::new(module_filename.to_str()?)
            .parent()
            .ok_or_else(|| anyhow::anyhow!("invalid path"))?
            .join("Mitmproxy Redirector.app.tar");
        let copy_task = macos::copy_redirector_app(redirector_tar)?;
        let conf = MacosConf;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(copy_task) = copy_task {
                tokio::task::spawn_blocking(copy_task)
                    .await
                    .map_err(|e| anyhow::anyhow!("failed to copy: {e}"))??;
            }
            let (server, conf_tx) =
                Server::init(conf, handle_tcp_stream, handle_udp_stream).await?;
            Ok(LocalRedirector::new(server, conf_tx))
        })
    }
    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    Err(pyo3::exceptions::PyNotImplementedError::new_err(
        LocalRedirector::unavailable_reason(),
    ))
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::{Context, Result};
    use std::path::{Path, PathBuf};
    use std::{env, fs};

    /// Ensure "Mitmproxy Redirector.app" is installed into /Applications and up-to-date.
    pub(super) fn copy_redirector_app(
        redirector_tar: PathBuf,
    ) -> PyResult<Option<impl FnOnce() -> Result<()>>> {
        if env::var_os("MITMPROXY_KEEP_REDIRECTOR").is_some_and(|x| x == "1") {
            log::info!("Using existing mitmproxy redirector app.");
            return Ok(None);
        }

        if !redirector_tar.exists() {
            return Err(anyhow::anyhow!("{} does not exist", redirector_tar.display()).into());
        }
        let expected_mtime = fs::metadata(&redirector_tar)
            .and_then(|x| x.modified())
            .context("failed to get mtime for redirector")?;

        let info_plist = Path::new("/Applications/Mitmproxy Redirector.app/Contents/Info.plist");
        if let Ok(actual_mtime) = fs::metadata(info_plist).and_then(|m| m.modified()) {
            if actual_mtime == expected_mtime {
                log::debug!("Existing mitmproxy redirector app is up-to-date.");
                return Ok(None);
            }
            log::info!("Updating mitmproxy redirector app...");
        } else {
            log::info!("Installing mitmproxy redirector app...");
        };

        Ok(Some(move || {
            let archive_file = fs::File::open(redirector_tar)?;
            let mut archive = tar::Archive::new(archive_file);
            let destination_path = Path::new("/Applications/Mitmproxy Redirector.app/");
            if destination_path.exists() {
                // archive.unpack with overwrite does not work, so we do this.
                fs::remove_dir_all(destination_path)
                    .context("failed to remove existing mitmproxy redirector app")?;
            }
            archive
                .unpack(destination_path.parent().unwrap())
                .context("failed to unpack redirector")?;
            fs::File::open(info_plist)
                .and_then(|f| f.set_modified(expected_mtime))
                .context("failed to set redirector mtime")
        }))
    }
}
