//! Screen shares from a synthetic source through the signaling server and LiveKit.

#[path = "../../session/tests/common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TestEnv, accept_next, request, start_host, viewer_event};
use sqlx::PgPool;
use surf_rac_capture::source::{SyntheticControl, SyntheticSource};
use surf_rac_capture::{FrameSource, ScreenShare, ShareOptions};
use surf_rac_protocol::data::{
    CaptureState, Control, DataMessage, PauseReason, QualityMode, ScreenState,
};
use surf_rac_session::SessionConfig;
use surf_rac_session::host::{HostEvent, HostSession};
use surf_rac_session::viewer::{ViewerEvent, ViewerSession};
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinHandle;

/// Forwards viewer joins and control messages from `events` to `share`.
fn wire(share: Arc<ScreenShare>, mut events: Receiver<HostEvent>) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(ev) = events.recv().await {
            match ev {
                HostEvent::ViewerJoined { viewer } => share.viewer_joined(viewer),
                HostEvent::DataReceived {
                    viewer,
                    message: DataMessage::Control(control),
                } => share.handle_control(viewer, &control),
                _ => {}
            }
        }
    })
}

/// A host sharing a synthetic screen and one connected viewer.
struct Shared {
    /// The share.
    share: Arc<ScreenShare>,
    /// Makes the synthetic source fail.
    control: SyntheticControl,
    /// The viewer.
    viewer: ViewerSession,
    /// The viewer's events.
    events: Receiver<ViewerEvent>,
    /// Keeps the host alive.
    _host: HostSession,
    /// Forwards host events to the share.
    _wire: JoinHandle<()>,
    /// Keeps the server alive.
    _env: TestEnv,
}

/// Starts a host sharing synthetic monitors of `sizes` and connects a viewer.
async fn shared(pool: PgPool, sizes: Vec<(u32, u32)>) -> Shared {
    let env = TestEnv::start(pool).await;
    let (h, v) = (env.device("host", 1).await, env.device("viewer", 2).await);
    let (host, mut host_events) = start_host(&h, SessionConfig::default()).await;
    let (source, control) = SyntheticSource::new(sizes);
    let share = Arc::new(
        ScreenShare::start_with_source(host.clone(), ShareOptions::default(), move || {
            Ok(Box::new(source) as Box<dyn FrameSource>)
        })
        .await
        .expect("share start"),
    );
    let pending = request(&v, h.id, SessionConfig::default());
    let (viewer, events) = accept_next(&host, &mut host_events, pending).await;
    let wire = wire(Arc::clone(&share), host_events);
    Shared {
        share,
        control,
        viewer,
        events,
        _host: host,
        _wire: wire,
        _env: env,
    }
}

/// Waits up to 15 s for a screen state matching `pred`.
async fn state_where(
    events: &mut Receiver<ViewerEvent>,
    pred: impl Fn(&ScreenState) -> bool,
) -> ScreenState {
    let ev = viewer_event(events, Duration::from_secs(15), |e| {
        matches!(e, ViewerEvent::DataReceived(DataMessage::Control(Control::ScreenState(s))) if pred(s))
    })
    .await;
    let ViewerEvent::DataReceived(DataMessage::Control(Control::ScreenState(s))) = ev else {
        unreachable!()
    };
    s
}

/// Waits up to 15 s for 5 video frames of `width` x `height`.
async fn frames_of(events: &mut Receiver<ViewerEvent>, width: u32, height: u32) {
    for _ in 0..5 {
        viewer_event(events, Duration::from_secs(15), |e| {
            matches!(e, ViewerEvent::VideoFrame(f) if (f.width, f.height) == (width, height))
        })
        .await;
    }
}

#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_sees_synthetic_screen_and_state(pool: PgPool) {
    let mut s = shared(pool, vec![(1280, 720), (640, 480)]).await;
    let state = state_where(&mut s.events, |_| true).await;
    assert_eq!(state.monitors.len(), 2);
    assert_eq!(state.selected, 0);
    assert_eq!(state.mode, QualityMode::Balanced);
    assert_eq!(state.capture, CaptureState::Active);
    frames_of(&mut s.events, 1280, 720).await;
    assert_eq!(s.share.state(), state);
}

#[sqlx::test(migrations = "../server/migrations")]
async fn viewer_switches_monitor_and_mode(pool: PgPool) {
    let mut s = shared(pool, vec![(1920, 1080), (640, 480)]).await;
    state_where(&mut s.events, |_| true).await;
    frames_of(&mut s.events, 1920, 1080).await;

    let msg = DataMessage::Control(Control::SelectMonitor { index: 1 });
    s.viewer.send(&msg).await.unwrap();
    state_where(&mut s.events, |st| st.selected == 1).await;
    frames_of(&mut s.events, 640, 480).await;

    s.viewer
        .send(&DataMessage::Control(Control::SelectMonitor { index: 0 }))
        .await
        .unwrap();
    s.viewer
        .send(&DataMessage::Control(Control::SetQuality {
            mode: QualityMode::Speed,
        }))
        .await
        .unwrap();
    state_where(&mut s.events, |st| st.selected == 0 && st.mode == QualityMode::Speed).await;
    frames_of(&mut s.events, 1280, 720).await;
}

#[sqlx::test(migrations = "../server/migrations")]
async fn source_failure_pauses_and_resumes(pool: PgPool) {
    let mut s = shared(pool, vec![(640, 480)]).await;
    state_where(&mut s.events, |_| true).await;
    frames_of(&mut s.events, 640, 480).await;
    s.control.fail_next(3);
    state_where(&mut s.events, |st| {
        st.capture
            == CaptureState::Paused {
                reason: PauseReason::Recovering,
            }
    })
    .await;
    state_where(&mut s.events, |st| st.capture == CaptureState::Active).await;
    frames_of(&mut s.events, 640, 480).await;
}
