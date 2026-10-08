//! Capture of this machine's real monitors. Runs on Windows only.

#![cfg(windows)]

use std::time::{Duration, Instant};

use surf_rac_capture::FrameSource;
use surf_rac_capture::convert::{BgraFrame, to_i420};
use surf_rac_capture::desktop::DesktopSource;
use surf_rac_capture::mode::target_size;
use surf_rac_protocol::data::QualityMode;

/// Captures until a frame arrives, for at most 1 s.
fn first_frame(source: &mut DesktopSource) -> BgraFrame {
    let deadline = Instant::now() + Duration::from_secs(1);
    while Instant::now() < deadline {
        if let Ok(Some(frame)) = source.capture() {
            return frame;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("no frame within 1 s");
}

/// Returns the index of the primary monitor.
fn primary(source: &mut DesktopSource) -> usize {
    let monitors = source.monitors().expect("monitors");
    monitors.iter().position(|m| m.primary).expect("a primary monitor")
}

#[test]
fn enumerates_at_least_one_monitor() {
    let mut source = DesktopSource::new().expect("desktop source");
    let monitors = source.monitors().expect("monitors");
    for m in &monitors {
        println!("monitor {:?} {}x{} primary={}", m.name, m.width, m.height, m.primary);
    }
    assert!(!monitors.is_empty());
    assert_eq!(monitors.iter().filter(|m| m.primary).count(), 1);
    assert!(monitors.iter().all(|m| m.width > 0 && m.height > 0 && !m.name.is_empty()));
}

#[test]
fn captures_monitor_sized_non_uniform_frame() {
    let mut source = DesktopSource::new().expect("desktop source");
    let index = primary(&mut source);
    let monitor = source.monitors().unwrap()[index].clone();
    source.select(index).expect("select");
    let frame = first_frame(&mut source);
    assert_eq!((frame.width, frame.height), (monitor.width, monitor.height));
    let first = &frame.data[..4];
    assert!(
        frame.data.chunks(4).any(|px| px[..3] != first[..3]),
        "every pixel has the same colour"
    );
}

#[test]
fn capture_and_convert_median_under_10ms() {
    let mut source = DesktopSource::new().expect("desktop source");
    let index = primary(&mut source);
    source.select(index).expect("select");
    first_frame(&mut source);
    let mut times = Vec::new();
    for _ in 0..60 {
        let started = Instant::now();
        if let Ok(Some(frame)) = source.capture() {
            let (w, h) = target_size(QualityMode::Balanced, frame.width, frame.height);
            let _ = to_i420(&frame, w, h, 0);
            times.push(started.elapsed());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(times.len() >= 30, "only {} of 60 captures produced a frame", times.len());
    times.sort();
    let median = times[times.len() / 2];
    println!("capture + convert median {median:?} over {} frames", times.len());
    assert!(median < Duration::from_millis(10), "median {median:?}");
}
