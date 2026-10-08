//! Capture of this machine's real monitors. Runs on Windows only.

#![cfg(windows)]

use std::time::{Duration, Instant};

use surf_rac_capture::FrameSource;
use surf_rac_capture::convert::{BgraFrame, to_i420};
use surf_rac_capture::desktop::DesktopSource;
use surf_rac_capture::h264::{NAL_IDR, NAL_SPS, nal_types};
use surf_rac_capture::mf::{EncodeError, MfEncoder};
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

/// Returns a `w` x `h` NV12 frame with a white bar at a position set by `n`.
fn nv12_bar(w: u32, h: u32, n: u32) -> Vec<u8> {
    let (w, h) = (w as usize, h as usize);
    let mut data = vec![16u8; w * h];
    let x0 = (n as usize * 16) % w;
    for row in data.chunks_mut(w) {
        for px in row.iter_mut().skip(x0).take(64) {
            *px = 235;
        }
    }
    data.resize(w * h * 3 / 2, 128);
    data
}

/// Creates a hardware encoder, or returns `None` and says so when this machine has none.
fn hardware(w: u32, h: u32) -> Option<MfEncoder> {
    match MfEncoder::new(w, h, 5_000_000, 30) {
        Ok(enc) => {
            println!("hardware encoder: {}", enc.adapter_name());
            Some(enc)
        }
        Err(EncodeError::NoHardware) => {
            eprintln!("no hardware H.264 encoder on this machine; skipped");
            None
        }
        Err(e) => panic!("encoder: {e}"),
    }
}

/// Microseconds between frames at 30 fps.
const FRAME_US: i64 = 33_333;

/// Polls `enc` for up to 200 ms and returns the access units that come out.
fn drain(enc: &mut MfEncoder) -> Vec<surf_rac_capture::mf::EncodedAu> {
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_millis(200);
    while Instant::now() < deadline {
        out.extend(enc.poll().unwrap());
        std::thread::sleep(Duration::from_millis(2));
    }
    out
}

#[test]
fn encodes_idr_first() {
    let Some(mut enc) = hardware(1280, 720) else { return };
    let mut aus = Vec::new();
    for n in 0..10 {
        aus.extend(enc.encode(&nv12_bar(1280, 720, n), i64::from(n) * FRAME_US, false).unwrap());
    }
    aus.extend(drain(&mut enc));
    assert!(aus.len() >= 5, "only {} access units for 10 frames", aus.len());
    let first = &aus[0];
    let types = nal_types(&first.data);
    assert!(first.keyframe, "first access unit is not a keyframe: {types:?}");
    assert!(types.contains(&NAL_SPS) && types.contains(&NAL_IDR), "{types:?}");
    assert!(aus[1..].iter().any(|au| !au.keyframe), "every access unit is a keyframe");
}

#[test]
fn forced_keyframe_within_two_frames() {
    let Some(mut enc) = hardware(1280, 720) else { return };
    let mut aus = Vec::new();
    for n in 0..15 {
        aus.extend(enc.encode(&nv12_bar(1280, 720, n), i64::from(n) * FRAME_US, false).unwrap());
    }
    let forced = 15 * FRAME_US;
    for n in 15..20 {
        let force = n == 15;
        aus.extend(enc.encode(&nv12_bar(1280, 720, n), i64::from(n) * FRAME_US, force).unwrap());
    }
    aus.extend(drain(&mut enc));
    let key = aus
        .iter()
        .find(|au| au.keyframe && au.timestamp_us >= forced)
        .expect("no keyframe after the request");
    assert!(key.timestamp_us <= forced + FRAME_US, "keyframe at {} us", key.timestamp_us);
    assert!(nal_types(&key.data).contains(&NAL_SPS));
}

#[test]
fn encode_median_under_15ms_1080p() {
    let Some(mut enc) = hardware(1920, 1080) else { return };
    let mut times = Vec::new();
    let mut count = 0;
    for n in 0..60 {
        let frame = nv12_bar(1920, 1080, n);
        let started = Instant::now();
        count += enc.encode(&frame, i64::from(n) * FRAME_US, false).unwrap().len();
        times.push(started.elapsed());
    }
    count += drain(&mut enc).len();
    times.sort();
    let median = times[30];
    println!("hardware encode median {median:?}, {count} access units for 60 frames");
    assert!(count >= 55, "only {count} access units for 60 frames");
    assert!(median < Duration::from_millis(15), "median {median:?}");
}

#[test]
fn paced_frames_keep_up_with_30_fps() {
    let Some(mut enc) = hardware(1920, 1080) else { return };
    let started = Instant::now();
    let (mut count, mut busy) = (0, Duration::ZERO);
    for n in 0..60u32 {
        let frame = nv12_bar(1920, 1080, n);
        let t = Instant::now();
        count += enc.encode(&frame, i64::from(n) * FRAME_US, false).unwrap().len();
        busy += t.elapsed();
        let next = started + Duration::from_micros(33_333) * (n + 1);
        while Instant::now() < next {
            count += enc.poll().unwrap().len();
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    count += drain(&mut enc).len();
    println!("paced: {count} access units for 60 frames, encode calls {:?} on average", busy / 60);
    assert!(count >= 58, "only {count} access units for 60 frames");
    assert!(busy / 60 < Duration::from_millis(33), "encode calls take {:?} on average", busy / 60);
}

#[test]
fn bitrate_change_is_accepted() {
    let Some(mut enc) = hardware(640, 480) else { return };
    enc.encode(&nv12_bar(640, 480, 0), 0, false).unwrap();
    enc.set_bitrate(2_500_000).unwrap();
    enc.encode(&nv12_bar(640, 480, 1), FRAME_US, false).unwrap();
}
