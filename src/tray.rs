//! Windows system-tray integration for `serve --tray`.
//!
//! The tray is a thin client of the localhost HTTP API, exactly like the
//! browser UI: the tray thread shares no state with the server and only
//! POSTs to `http://127.0.0.1:<port>/api/...`, so the engine stays decoupled
//! and testable. On non-Windows targets the tray is stubbed out with a
//! warning; `serve` keeps running either way.

use std::sync::atomic::{AtomicBool, Ordering};

/// Set by the tray's Exit menu item; `serve` polls it to trigger graceful
/// shutdown. Never set on non-Windows (no tray there), so the poll is a cheap
/// always-false no-op on those platforms.
static EXIT_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Name of the `HKCU\...\CurrentVersion\Run` value backing `serve --autostart`.
pub const RUN_VALUE_NAME: &str = "CF-Scanner";

pub fn exit_requested() -> bool {
    EXIT_REQUESTED.load(Ordering::Relaxed)
}

/// `HKCU\...\Run` value payload: the quoted exe path plus the `serve` flags
/// the autostart entry must launch. Pure so the quoting/arg shape is unit
/// testable without touching the registry.
#[cfg(any(target_os = "windows", test))]
fn autostart_command(exe: &std::path::Path) -> String {
    format!("\"{}\" serve --tray", exe.display())
}

/// "Start CDN scan" menu payload: CLI defaults (quick preset, port 443).
/// `Cdn`/`Preset`/`Quick` are the externally-tagged serde shapes
/// `ScanConfig` actually deserializes from (lowercase variants would 400).
#[cfg(any(target_os = "windows", test))]
fn cdn_payload() -> serde_json::Value {
    serde_json::json!({
        "mode": "Cdn",
        "target": { "Preset": "Quick" },
        "ports": [443],
        "stop": { "found": 20, "cap": null },
        "exclude": [],
        "custom_cidrs": [],
        "concurrency": 64,
        "timeout_ms": 3000,
        "phase2": null,
        "warp": null,
    })
}

/// "Start WARP scan" menu payload: 40 endpoints on the WARP ports.
#[cfg(any(target_os = "windows", test))]
fn warp_payload() -> serde_json::Value {
    serde_json::json!({
        "mode": "Warp",
        "target": { "Count": 40 },
        "ports": [2408, 500],
        "stop": { "found": 10, "cap": null },
        "exclude": [],
        "custom_cidrs": [],
        "concurrency": 64,
        "timeout_ms": 3000,
        "phase2": null,
        "warp": {
            "custom_endpoints": [],
            "probes_per_endpoint": 3,
            "wgconf": null,
            "verify_with_wgconf": false,
        },
    })
}

#[cfg(target_os = "windows")]
mod imp {
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use anyhow::{Context, Result};
    use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
    use tray_icon::{Icon, TrayIconBuilder};

    use super::{RUN_VALUE_NAME, autostart_command, cdn_payload, warp_payload};

    /// Spawns the tray thread. The icon is created on a dedicated std thread
    /// (not tokio) that also pumps the tray window's Win32 messages; menu
    /// actions are blocking HTTP calls against the localhost API.
    pub fn spawn(api_base: String, open_ui: bool) -> Result<()> {
        std::thread::Builder::new()
            .name("cf-scanner-tray".to_owned())
            .spawn(move || tray_thread(api_base, open_ui))
            .context("could not spawn tray thread")?;
        Ok(())
    }

    fn tray_thread(api_base: String, open_ui: bool) {
        // A tray that fails to come up (headless session, explorer not ready)
        // must never take down serve: log and return, the server keeps running.
        if let Err(err) = run_tray(&api_base, open_ui) {
            tracing::warn!("system tray unavailable, serving without it: {err:#}");
        }
    }

    fn run_tray(api_base: &str, open_ui: bool) -> Result<()> {
        let open_ui_item = MenuItem::new("Open UI", true, None);
        let cdn_item = MenuItem::new("Start CDN scan", true, None);
        let warp_item = MenuItem::new("Start WARP scan", true, None);
        let cancel_item = MenuItem::new("Cancel", true, None);
        let exit_item = MenuItem::new("Exit", true, None);
        let separator = PredefinedMenuItem::separator();
        let menu = Menu::new();
        menu.append_items(&[
            &open_ui_item,
            &cdn_item,
            &warp_item,
            &cancel_item,
            &separator,
            &exit_item,
        ])?;
        // The icon stays alive as long as `_tray` lives on this thread.
        let _tray = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("CF-Scanner")
            .with_icon(Icon::from_rgba(tray_icon_rgba(), 32, 32)?)
            .build()
            .context("could not create tray icon")?;
        if open_ui {
            open_browser(api_base);
        }
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("could not build tray HTTP client")?;
        loop {
            pump_messages();
            for event in MenuEvent::receiver().try_iter() {
                if event.id == *open_ui_item.id() {
                    open_browser(api_base);
                } else if event.id == *cdn_item.id() {
                    post_scan(&client, api_base, &cdn_payload());
                } else if event.id == *warp_item.id() {
                    post_scan(&client, api_base, &warp_payload());
                } else if event.id == *cancel_item.id() {
                    post_cancel(&client, api_base);
                } else if event.id == *exit_item.id() {
                    request_exit();
                    return Ok(());
                }
            }
            if super::exit_requested() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn post_scan(client: &reqwest::blocking::Client, api_base: &str, payload: &serde_json::Value) {
        let response = client
            .post(format!("{api_base}/api/scan"))
            .json(payload)
            .send();
        match response {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => tracing::warn!("tray: scan request rejected ({})", response.status()),
            Err(err) => tracing::warn!("tray: scan request failed: {err}"),
        }
    }

    fn post_cancel(client: &reqwest::blocking::Client, api_base: &str) {
        match client.post(format!("{api_base}/api/cancel")).send() {
            Ok(response) if response.status().is_success() => {}
            Ok(response) => tracing::warn!("tray: cancel request rejected ({})", response.status()),
            Err(err) => tracing::warn!("tray: cancel request failed: {err}"),
        }
    }

    fn request_exit() {
        super::EXIT_REQUESTED.store(true, Ordering::Relaxed);
    }

    /// Registers/removes the `HKCU\...\CurrentVersion\Run` entry that starts
    /// `serve --tray` at logon; deleting a missing value is Ok.
    pub fn set_autostart(enabled: bool) -> Result<()> {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;

        const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
        let run_key = RegKey::predef(HKEY_CURRENT_USER)
            .create_subkey(RUN_KEY)
            .context("could not open HKCU Run key")?
            .0;
        if enabled {
            let exe = std::env::current_exe().context("could not resolve current exe path")?;
            run_key
                .set_value(RUN_VALUE_NAME, &autostart_command(&exe))
                .with_context(|| format!("could not write {RUN_VALUE_NAME} autostart value"))?;
        } else if let Err(err) = run_key.delete_value(RUN_VALUE_NAME) {
            if err.kind() != std::io::ErrorKind::NotFound {
                return Err(err)
                    .with_context(|| format!("could not remove {RUN_VALUE_NAME} autostart value"));
            }
        }
        Ok(())
    }

    /// Opens the UI in the default browser via `cmd /c start`.
    fn open_browser(url: &str) {
        match std::process::Command::new("cmd")
            .args(["/c", "start", "", url])
            .spawn()
        {
            Ok(_) => {}
            Err(err) => tracing::warn!("tray: could not open browser: {err}"),
        }
    }

    /// 32x32 RGBA tray glyph (a solid CF-orange circle with an anti-aliased
    /// edge) — drawn in code so the tray needs no icon asset pipeline.
    fn tray_icon_rgba() -> Vec<u8> {
        const SIZE: u32 = 32;
        let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
        for y in 0..SIZE {
            for x in 0..SIZE {
                let dx = x as f64 + 0.5 - 16.0;
                let dy = y as f64 + 0.5 - 16.0;
                let dist = (dx * dx + dy * dy).sqrt();
                let (r, g, b, a) = if dist <= 13.0 {
                    (0xF3, 0x80, 0x20, 255)
                } else if dist <= 15.0 {
                    (0xF3, 0x80, 0x20, ((15.0 - dist) * 128.0) as u8)
                } else {
                    (0, 0, 0, 0)
                };
                let i = ((y * SIZE + x) * 4) as usize;
                rgba[i] = r;
                rgba[i + 1] = g;
                rgba[i + 2] = b;
                rgba[i + 3] = a;
            }
        }
        rgba
    }

    /// Minimal Win32 message pump for the tray window: tray-icon ships no
    /// pump, and menu clicks surface only as `WM_COMMAND` dispatched to the
    /// tray hwnd, so this thread must dispatch them itself. PeekMessage polls
    /// with a short sleep so the loop can also drain menu events and the exit
    /// flag without a message arriving. Raw FFI keeps the approved dependency
    /// list unchanged.
    fn pump_messages() {
        unsafe {
            let mut msg: Msg = std::mem::zeroed();
            while PeekMessageW(&mut msg, 0, 0, 0, PM_REMOVE) != 0 {
                if msg.message == WM_QUIT {
                    return;
                }
                let _ = TranslateMessage(&msg);
                let _ = DispatchMessageW(&msg);
            }
        }
    }

    #[repr(C)]
    struct Point {
        x: i32,
        y: i32,
    }

    #[repr(C)]
    struct Msg {
        hwnd: *mut core::ffi::c_void,
        message: u32,
        wparam: usize,
        lparam: isize,
        time: u32,
        pt: Point,
    }

    const WM_QUIT: u32 = 0x0012;
    const PM_REMOVE: u32 = 0x0001;

    #[link(name = "user32")]
    unsafe extern "system" {
        fn PeekMessageW(lpmsg: *mut Msg, hwnd: isize, wmin: u32, wmax: u32, remove: u32) -> i32;
        fn TranslateMessage(lpmsg: *const Msg) -> i32;
        fn DispatchMessageW(lpmsg: *const Msg) -> isize;
    }
}

#[cfg(not(target_os = "windows"))]
mod imp {
    pub fn spawn(_api_base: String, _open_ui: bool) -> anyhow::Result<()> {
        eprintln!("tray not supported on this platform; serving without it");
        Ok(())
    }

    pub fn set_autostart(_enabled: bool) -> anyhow::Result<()> {
        eprintln!("autostart not supported on this platform");
        Ok(())
    }
}

pub use imp::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::types::{CdnPreset, Mode, ScanConfig, ScanTarget};

    #[test]
    fn cdn_payload_is_a_valid_scan_config() {
        let cfg: ScanConfig = serde_json::from_value(cdn_payload()).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode, Mode::Cdn);
        assert_eq!(cfg.target, ScanTarget::Preset(CdnPreset::Quick));
        assert_eq!(cfg.ports, vec![443]);
        assert_eq!(cfg.stop.found, 20);
        assert_eq!(cfg.stop.cap, None);
        assert_eq!(cfg.concurrency, 64);
        assert_eq!(cfg.timeout_ms, 3000);
        assert!(cfg.phase2.is_none());
        assert!(cfg.warp.is_none());
    }

    #[test]
    fn warp_payload_is_a_valid_scan_config() {
        let cfg: ScanConfig = serde_json::from_value(warp_payload()).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.mode, Mode::Warp);
        assert_eq!(cfg.target, ScanTarget::Count(40));
        assert_eq!(cfg.ports, vec![2408, 500]);
        assert_eq!(cfg.stop.found, 10);
        assert_eq!(cfg.stop.cap, None);
        assert_eq!(cfg.concurrency, 64);
        assert_eq!(cfg.timeout_ms, 3000);
        let warp = cfg.warp.unwrap();
        assert!(warp.custom_endpoints.is_empty());
        assert_eq!(warp.probes_per_endpoint, 3);
        assert!(!warp.verify_with_wgconf);
    }

    #[test]
    fn autostart_command_quotes_the_exe_path() {
        assert_eq!(
            autostart_command(std::path::Path::new(r"C:\Program Files\cf-scanner.exe")),
            "\"C:\\Program Files\\cf-scanner.exe\" serve --tray"
        );
        assert_eq!(
            autostart_command(std::path::Path::new(r"C:\cf-scanner.exe")),
            "\"C:\\cf-scanner.exe\" serve --tray"
        );
    }

    #[test]
    fn exit_requested_is_false_by_default() {
        assert!(!exit_requested());
    }
}
