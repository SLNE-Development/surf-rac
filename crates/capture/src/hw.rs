//! Hardware encoding on its own thread, so a slow encoder never stalls capture.
//!
//! The capture thread hands the worker one frame at a time. While the worker
//! is still busy with a frame, further frames are refused and dropped. The
//! worker publishes access units itself, switches the session's track to
//! encoded input when its first encoder opens, and back to raw input when the
//! encoder fails, before reporting the failure.

use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use surf_rac_session::{EncodedFrame, VideoInput};

use crate::h264::{EncodeError, EncodedAu};
use crate::share::VideoSink;

/// Longest time between two polls of the encoder for finished frames.
const POLL_INTERVAL: Duration = Duration::from_millis(4);

/// An H.264 encoder for frames of one size.
pub(crate) trait HwEncoder {
    /// Returns the encoder's display name.
    fn name(&self) -> &str;
    /// Returns the frame size it encodes.
    fn size(&self) -> (u32, u32);
    /// Feeds one NV12 frame; returns the access units that are ready.
    fn encode(
        &mut self,
        nv12: &[u8],
        timestamp_us: i64,
        force_keyframe: bool,
    ) -> Result<Vec<EncodedAu>, EncodeError>;
    /// Returns the access units that became ready since the last call.
    fn poll(&mut self) -> Result<Vec<EncodedAu>, EncodeError>;
    /// Sets the target bitrate in bits per second.
    fn set_bitrate(&mut self, bitrate_bps: u64) -> Result<(), EncodeError>;
}

#[cfg(windows)]
impl HwEncoder for crate::mf::MfEncoder {
    /// Returns the Media Foundation encoder's name.
    fn name(&self) -> &str {
        self.adapter_name()
    }

    /// Returns the size the encoder was opened for.
    fn size(&self) -> (u32, u32) {
        crate::mf::MfEncoder::size(self)
    }

    /// Forwards to [`crate::mf::MfEncoder::encode`].
    fn encode(
        &mut self,
        nv12: &[u8],
        timestamp_us: i64,
        force_keyframe: bool,
    ) -> Result<Vec<EncodedAu>, EncodeError> {
        crate::mf::MfEncoder::encode(self, nv12, timestamp_us, force_keyframe)
    }

    /// Forwards to [`crate::mf::MfEncoder::poll`].
    fn poll(&mut self) -> Result<Vec<EncodedAu>, EncodeError> {
        crate::mf::MfEncoder::poll(self)
    }

    /// Forwards to [`crate::mf::MfEncoder::set_bitrate`].
    fn set_bitrate(&mut self, bitrate_bps: u64) -> Result<(), EncodeError> {
        crate::mf::MfEncoder::set_bitrate(self, bitrate_bps)
    }
}

/// Opens a hardware encoder for `width` x `height` at a bitrate; runs on the worker thread.
pub(crate) type HwFactory =
    Box<dyn FnMut(u32, u32, u64) -> Result<Box<dyn HwEncoder>, EncodeError> + Send>;

/// One frame for the worker.
pub(crate) struct Job {
    /// Tightly packed NV12 pixels.
    pub(crate) nv12: Vec<u8>,
    /// Width in pixels.
    pub(crate) width: u32,
    /// Height in pixels.
    pub(crate) height: u32,
    /// Capture time in microseconds.
    pub(crate) timestamp_us: i64,
    /// Whether this frame must be a keyframe.
    pub(crate) force_keyframe: bool,
    /// Bitrate the encoder should target.
    pub(crate) bitrate_bps: u64,
}

/// A running hardware encoding thread.
pub(crate) struct HwWorker {
    /// Frames for the worker; one may wait while it encodes another.
    jobs: Option<SyncSender<Job>>,
    /// The failure that ended the worker.
    failed: Receiver<EncodeError>,
    /// The worker thread.
    thread: Option<JoinHandle<()>>,
}

impl HwWorker {
    /// Starts a worker that opens encoders with `factory` and publishes on `sink`.
    pub(crate) fn start<K: VideoSink + Clone>(factory: HwFactory, sink: K) -> HwWorker {
        let (jobs, job_rx) = mpsc::sync_channel(1);
        let (failed_tx, failed) = mpsc::channel();
        let thread = thread::Builder::new()
            .name("surf-rac-encode".into())
            .spawn(move || Worker::new(factory, sink, failed_tx).run(job_rx))
            .ok();
        HwWorker {
            jobs: Some(jobs),
            failed,
            thread,
        }
    }

    /// Hands `job` to the worker; returns false when the worker is busy and the frame is dropped.
    pub(crate) fn submit(&self, job: Job) -> bool {
        let Some(jobs) = &self.jobs else { return false };
        match jobs.try_send(job) {
            Ok(()) => true,
            Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => false,
        }
    }

    /// Returns the failure that ended the worker, once it has ended.
    pub(crate) fn failure(&self) -> Option<EncodeError> {
        self.failed.try_recv().ok()
    }
}

impl Drop for HwWorker {
    /// Stops the worker and waits for it to release its encoder.
    fn drop(&mut self) {
        self.jobs = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The worker thread's state.
struct Worker<K: VideoSink> {
    /// Opens encoders.
    factory: HwFactory,
    /// Where access units go.
    sink: K,
    /// Reports the failure that ends the worker.
    failed: Sender<EncodeError>,
    /// The open encoder.
    encoder: Option<Box<dyn HwEncoder>>,
    /// Whether the session's track was switched to encoded input.
    encoded_input: bool,
    /// The bitrate the encoder targets.
    bitrate_bps: u64,
    /// Size of the latest frame.
    size: (u32, u32),
}

impl<K: VideoSink> Worker<K> {
    /// Creates the worker state.
    fn new(factory: HwFactory, sink: K, failed: Sender<EncodeError>) -> Worker<K> {
        Worker {
            factory,
            sink,
            failed,
            encoder: None,
            encoded_input: false,
            bitrate_bps: 0,
            size: (0, 0),
        }
    }

    /// Encodes jobs and polls for output until the job sender is gone or the encoder fails.
    fn run(mut self, jobs: Receiver<Job>) {
        loop {
            let result = match jobs.recv_timeout(POLL_INTERVAL) {
                Ok(job) => self.encode(job),
                Err(RecvTimeoutError::Timeout) => self.poll(),
                Err(RecvTimeoutError::Disconnected) => return,
            };
            if let Err(e) = result {
                self.fail(e);
                return;
            }
        }
    }

    /// Encodes one frame, opening an encoder for its size first when needed.
    fn encode(&mut self, job: Job) -> Result<(), EncodeError> {
        self.size = (job.width, job.height);
        let mut force = job.force_keyframe;
        if self.encoder.as_ref().map(|e| e.size()) != Some(self.size) {
            self.encoder = None;
            let encoder = (self.factory)(job.width, job.height, job.bitrate_bps)?;
            if !self.encoded_input {
                tracing::info!(encoder = encoder.name(), "encoder: hardware");
                self.sink
                    .switch_input(VideoInput::Encoded, job.width, job.height)
                    .map_err(EncodeError::Track)?;
                self.encoded_input = true;
            }
            self.encoder = Some(encoder);
            self.bitrate_bps = job.bitrate_bps;
            force = true;
        }
        let encoder = self.encoder.as_mut().ok_or(EncodeError::NoHardware)?;
        if job.bitrate_bps != self.bitrate_bps {
            if let Err(e) = encoder.set_bitrate(job.bitrate_bps) {
                tracing::debug!(error = %e, "bitrate change refused");
            }
            self.bitrate_bps = job.bitrate_bps;
        }
        let aus = encoder.encode(&job.nv12, job.timestamp_us, force)?;
        self.publish(aus);
        Ok(())
    }

    /// Publishes the access units the encoder finished.
    fn poll(&mut self) -> Result<(), EncodeError> {
        let Some(encoder) = self.encoder.as_mut() else {
            return Ok(());
        };
        let aus = encoder.poll()?;
        self.publish(aus);
        Ok(())
    }

    /// Publishes access units of the current frame size on the pass-through track.
    fn publish(&self, aus: Vec<EncodedAu>) {
        let (width, height) = self.size;
        for au in aus {
            let frame = EncodedFrame {
                width,
                height,
                timestamp_us: au.timestamp_us,
                keyframe: au.keyframe,
                data: &au.data,
            };
            if let Err(e) = self.sink.publish_encoded(&frame) {
                tracing::debug!(error = %e, "access unit not published");
            }
        }
    }

    /// Releases the encoder, switches the track back to raw input and reports `err`.
    fn fail(&mut self, err: EncodeError) {
        self.encoder = None;
        if self.encoded_input {
            let (w, h) = self.size;
            if let Err(e) = self.sink.switch_input(VideoInput::Raw, w, h) {
                tracing::warn!(error = %e, "switching the track to raw frames failed");
            }
        }
        let _ = self.failed.send(err);
    }
}
