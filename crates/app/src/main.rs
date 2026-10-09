//! Entry point of the surf-rac client.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Arc;

use eframe::egui;
use surf_rac_app::runtime::Runtime;
use surf_rac_app::store::{Store, default_dir};
use surf_rac_app::ui::ClientApp;

/// Makes the process per-monitor DPI aware before any window exists, so
/// window, capture and input coordinates are all physical pixels.
#[cfg(windows)]
fn set_dpi_awareness() {
    use windows::Win32::UI::HiDpi::{
        DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, SetProcessDpiAwarenessContext,
    };
    // SAFETY: called once at start-up, before any window is created.
    if let Err(e) =
        unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) }
    {
        tracing::warn!(error = %e, "per-monitor DPI awareness not set");
    }
}

/// Does nothing off Windows.
#[cfg(not(windows))]
fn set_dpi_awareness() {}

/// Starts logging, the runtime and the main window.
fn main() -> eframe::Result {
    let _log = surf_rac_app::logging::init();
    set_dpi_awareness();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), "surf-rac starting");
    let store = Store::open(default_dir());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("surf-rac")
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([760.0, 560.0]),
        ..Default::default()
    };
    eframe::run_native(
        "surf-rac",
        options,
        Box::new(move |cc| {
            let ctx = cc.egui_ctx.clone();
            let runtime = Runtime::start(store, Arc::new(move || ctx.request_repaint()))?;
            Ok(Box::new(ClientApp::new(&cc.egui_ctx, runtime)))
        }),
    )
}
