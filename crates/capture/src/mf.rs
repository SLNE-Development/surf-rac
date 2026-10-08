//! Hardware H.264 encoding through a Media Foundation transform.
//!
//! Hardware encoder MFTs are asynchronous: they ask for input and announce
//! output through events. [`MfEncoder`] drives them from one thread by
//! polling those events: [`MfEncoder::encode`] feeds one NV12 frame and
//! [`MfEncoder::poll`] collects access units as they become ready, without
//! waiting for the encoder.

use std::time::{Duration, Instant};

use windows::Win32::Media::MediaFoundation::{
    CODECAPI_AVEncCommonMeanBitRate, CODECAPI_AVEncCommonRateControlMode,
    CODECAPI_AVEncMPVDefaultBPictureCount, CODECAPI_AVEncMPVGOPSize,
    CODECAPI_AVEncVideoForceKeyFrame, CODECAPI_AVLowLatencyMode, ICodecAPI, IMFActivate,
    IMFMediaEventGenerator, IMFMediaType, IMFSample, IMFTransform, METransformHaveOutput,
    METransformNeedInput, MF_E_NO_EVENTS_AVAILABLE, MF_E_TRANSFORM_NEED_MORE_INPUT,
    MF_E_TRANSFORM_STREAM_CHANGE, MF_EVENT_FLAG_NO_WAIT, MF_LOW_LATENCY, MF_MT_AVG_BITRATE,
    MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE,
    MF_MT_MPEG_SEQUENCE_HEADER, MF_MT_MPEG2_PROFILE, MF_MT_SUBTYPE, MF_TRANSFORM_ASYNC_UNLOCK,
    MF_VERSION, MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video,
    MFSTARTUP_FULL, MFSampleExtension_CleanPoint, MFShutdown, MFStartup,
    MFT_CATEGORY_VIDEO_ENCODER, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_COMMAND_FLUSH, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING,
    MFT_MESSAGE_NOTIFY_END_OF_STREAM, MFT_MESSAGE_NOTIFY_END_STREAMING,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES, MFT_OUTPUT_STREAM_PROVIDES_SAMPLES,
    MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264, MFVideoFormat_NV12,
    MFVideoInterlace_Progressive, eAVEncCommonRateControlMode_CBR, eAVEncH264VProfile_Base,
};
use windows::Win32::System::Com::{COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree};
use windows::Win32::System::Variant::VARIANT;
use windows::core::{GUID, Interface, PWSTR};

pub use crate::h264::{EncodeError, EncodedAu};
use crate::h264::{NAL_SPS, nal_types};

/// Longest time one call waits for the encoder to accept input.
const INPUT_TIMEOUT: Duration = Duration::from_millis(200);

/// Media Foundation time units (100 ns) per microsecond.
const UNITS_PER_US: i64 = 10;

impl From<windows::core::Error> for EncodeError {
    /// Keeps the HRESULT of a failed Media Foundation call.
    fn from(e: windows::core::Error) -> Self {
        EncodeError::Hresult(e.code().0 as u32)
    }
}

/// A hardware H.264 encoder for NV12 frames of one size.
pub struct MfEncoder {
    /// The encoder transform.
    transform: IMFTransform,
    /// Its event source.
    events: IMFMediaEventGenerator,
    /// Its codec settings.
    codec: ICodecAPI,
    /// The activation object, shut down on drop.
    activate: IMFActivate,
    /// Display name of the encoder.
    name: String,
    /// Frame width in pixels.
    width: u32,
    /// Frame height in pixels.
    height: u32,
    /// Duration of one frame in 100 ns units.
    frame_duration: i64,
    /// Input requests not yet answered with a frame.
    need_input: u32,
    /// Whether the transform allocates its own output samples.
    provides_samples: bool,
    /// Size of an output buffer when this side allocates them.
    output_size: u32,
    /// Keeps Media Foundation started; declared last so it is released after
    /// every Media Foundation object above.
    _runtime: MfRuntime,
}

/// A started Media Foundation platform, shut down on drop.
struct MfRuntime;

impl MfRuntime {
    /// Starts Media Foundation on this thread.
    fn start() -> Result<MfRuntime, EncodeError> {
        // SAFETY: MFStartup has no preconditions; every success is paired with
        // one MFShutdown in drop.
        unsafe { MFStartup(MF_VERSION, MFSTARTUP_FULL)? };
        Ok(MfRuntime)
    }
}

impl Drop for MfRuntime {
    /// Shuts Media Foundation down once.
    fn drop(&mut self) {
        // SAFETY: pairs the MFStartup in start.
        let _ = unsafe { MFShutdown() };
    }
}

impl MfEncoder {
    /// Opens the first hardware H.264 encoder for `width` x `height` NV12 frames
    /// at `fps`, targeting `bitrate_bps` with constant bitrate, low latency, no
    /// B-frames and the baseline profile.
    pub fn new(width: u32, height: u32, bitrate_bps: u64, fps: u32) -> Result<MfEncoder, EncodeError> {
        // SAFETY: Media Foundation and COM calls on objects this function owns;
        // every out pointer refers to a live local.
        unsafe {
            let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
            let runtime = MfRuntime::start()?;
            let activate = first_hardware_encoder()?.ok_or(EncodeError::NoHardware)?;
            let opened = open(&activate, width, height, bitrate_bps, fps).and_then(|(transform, name)| {
                let events = transform.cast::<IMFMediaEventGenerator>()?;
                let codec = transform.cast::<ICodecAPI>()?;
                let info = transform.GetOutputStreamInfo(0)?;
                Ok((transform, name, events, codec, info))
            });
            let (transform, name, events, codec, info) = match opened {
                Ok(parts) => parts,
                Err(e) => {
                    let _ = activate.ShutdownObject();
                    return Err(e);
                }
            };
            let flags = info.dwFlags as i32;
            let provides_samples = flags
                & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 | MFT_OUTPUT_STREAM_CAN_PROVIDE_SAMPLES.0)
                != 0;
            Ok(MfEncoder {
                transform,
                events,
                codec,
                activate,
                name,
                width,
                height,
                frame_duration: 10_000_000 / i64::from(fps.max(1)),
                need_input: 0,
                provides_samples,
                output_size: info.cbSize.max(width * height * 3 / 2),
                _runtime: runtime,
            })
        }
    }

    /// Returns the encoder's display name, e.g. the GPU vendor's encoder.
    pub fn adapter_name(&self) -> &str {
        &self.name
    }

    /// Returns the frame size the encoder was opened for.
    pub fn size(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Feeds one tightly packed NV12 frame captured at `timestamp_us`.
    ///
    /// Waits only until the encoder accepts input, then returns the access
    /// units that are ready, usually those of earlier frames; the output of
    /// this frame follows from later calls or [`MfEncoder::poll`].
    /// `force_keyframe` makes this frame an IDR.
    ///
    /// # Panics
    ///
    /// Panics when `nv12` is not `width * height * 3 / 2` bytes.
    pub fn encode(
        &mut self,
        nv12: &[u8],
        timestamp_us: i64,
        force_keyframe: bool,
    ) -> Result<Vec<EncodedAu>, EncodeError> {
        let expected = (self.width * self.height * 3 / 2) as usize;
        assert_eq!(nv12.len(), expected, "NV12 frame has the wrong size");
        let mut out = Vec::new();
        let deadline = Instant::now() + INPUT_TIMEOUT;
        while self.need_input == 0 {
            if !self.pump(&mut out)? {
                if Instant::now() >= deadline {
                    return Err(EncodeError::Stalled);
                }
                std::thread::sleep(Duration::from_micros(500));
            }
        }
        // SAFETY: COM calls on owned objects; the locked buffer is written
        // within its reported maximum length and unlocked before use.
        unsafe {
            if force_keyframe {
                self.codec
                    .SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &VARIANT::from(1u32))?;
            }
            let buffer = MFCreateMemoryBuffer(nv12.len() as u32)?;
            let mut ptr = std::ptr::null_mut();
            let mut max = 0;
            buffer.Lock(&mut ptr, Some(&mut max), None)?;
            std::ptr::copy_nonoverlapping(nv12.as_ptr(), ptr, nv12.len().min(max as usize));
            buffer.Unlock()?;
            buffer.SetCurrentLength(nv12.len() as u32)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(timestamp_us * UNITS_PER_US)?;
            sample.SetSampleDuration(self.frame_duration)?;
            self.transform.ProcessInput(0, &sample, 0)?;
        }
        self.need_input -= 1;
        while self.pump(&mut out)? {}
        Ok(out)
    }

    /// Returns the access units that became ready, without feeding a frame or waiting.
    pub fn poll(&mut self) -> Result<Vec<EncodedAu>, EncodeError> {
        let mut out = Vec::new();
        while self.pump(&mut out)? {}
        Ok(out)
    }

    /// Sets the target bitrate in bits per second.
    pub fn set_bitrate(&mut self, bitrate_bps: u64) -> Result<(), EncodeError> {
        let bps = bitrate_bps.min(u64::from(u32::MAX)) as u32;
        // SAFETY: a COM call on an owned interface with a live VARIANT.
        unsafe {
            self.codec
                .SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bps))?;
        }
        Ok(())
    }

    /// Handles one pending encoder event; returns false when none was pending.
    fn pump(&mut self, out: &mut Vec<EncodedAu>) -> Result<bool, EncodeError> {
        // SAFETY: a COM call on an owned interface.
        let event = match unsafe { self.events.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
            Ok(event) => event,
            Err(e) if e.code() == MF_E_NO_EVENTS_AVAILABLE => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        // SAFETY: a COM call on an owned event.
        let kind = unsafe { event.GetType()? } as i32;
        if kind == METransformNeedInput.0 {
            self.need_input += 1;
        } else if kind == METransformHaveOutput.0 {
            if let Some(au) = self.take_output()? {
                out.push(au);
            }
        }
        Ok(true)
    }

    /// Takes one encoded sample from the transform.
    fn take_output(&mut self) -> Result<Option<EncodedAu>, EncodeError> {
        // SAFETY: COM calls on owned objects; the output buffer struct owns its
        // sample reference, which is taken back out of the ManuallyDrop below.
        unsafe {
            let provided = if self.provides_samples {
                None
            } else {
                let sample = MFCreateSample()?;
                sample.AddBuffer(&MFCreateMemoryBuffer(self.output_size)?)?;
                Some(sample)
            };
            let mut buffers = [MFT_OUTPUT_DATA_BUFFER {
                dwStreamID: 0,
                pSample: std::mem::ManuallyDrop::new(provided),
                dwStatus: 0,
                pEvents: std::mem::ManuallyDrop::new(None),
            }];
            let mut status = 0;
            let result = self.transform.ProcessOutput(0, &mut buffers, &mut status);
            let sample = std::mem::ManuallyDrop::take(&mut buffers[0].pSample);
            drop(std::mem::ManuallyDrop::take(&mut buffers[0].pEvents));
            match result {
                Ok(()) => {}
                Err(e) if e.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => return Ok(None),
                Err(e) if e.code() == MF_E_TRANSFORM_STREAM_CHANGE => {
                    let ty = self.transform.GetOutputAvailableType(0, 0)?;
                    self.transform.SetOutputType(0, &ty, 0)?;
                    return Ok(None);
                }
                Err(e) => return Err(e.into()),
            }
            let Some(sample) = sample else { return Ok(None) };
            self.access_unit(&sample).map(Some)
        }
    }

    /// Copies an output sample into an access unit, adding SPS and PPS before
    /// an IDR when the encoder left them out.
    fn access_unit(&self, sample: &IMFSample) -> Result<EncodedAu, EncodeError> {
        // SAFETY: COM calls on an owned sample; the locked range is read within
        // its reported current length and unlocked afterwards.
        unsafe {
            let buffer = sample.ConvertToContiguousBuffer()?;
            let mut ptr = std::ptr::null_mut();
            let mut len = 0;
            buffer.Lock(&mut ptr, None, Some(&mut len))?;
            let mut data = std::slice::from_raw_parts(ptr, len as usize).to_vec();
            buffer.Unlock()?;
            let keyframe = sample.GetUINT32(&MFSampleExtension_CleanPoint).unwrap_or(0) != 0;
            if keyframe && !nal_types(&data).contains(&NAL_SPS) {
                let mut header = self.sequence_header()?;
                header.extend_from_slice(&data);
                data = header;
            }
            let time = sample.GetSampleTime().unwrap_or(0);
            Ok(EncodedAu {
                data,
                keyframe,
                timestamp_us: time / UNITS_PER_US,
            })
        }
    }

    /// Returns the SPS and PPS of the current output type in Annex-B form.
    fn sequence_header(&self) -> Result<Vec<u8>, EncodeError> {
        // SAFETY: COM calls on an owned transform; the blob is read into a
        // buffer of the size the media type reports.
        unsafe {
            let ty = self.transform.GetOutputCurrentType(0)?;
            let size = ty.GetBlobSize(&MF_MT_MPEG_SEQUENCE_HEADER)?;
            let mut blob = vec![0u8; size as usize];
            ty.GetBlob(&MF_MT_MPEG_SEQUENCE_HEADER, &mut blob, None)?;
            Ok(blob)
        }
    }
}

impl Drop for MfEncoder {
    /// Ends the stream and shuts the encoder down; Media Foundation itself is
    /// released after the remaining fields.
    fn drop(&mut self) {
        // SAFETY: COM calls on owned objects during teardown; errors are ignored.
        unsafe {
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            let _ = self.activate.ShutdownObject();
        }
    }
}

/// Returns the best-ranked hardware encoder from NV12 to H.264, if any.
///
/// # Safety
///
/// Media Foundation must be started on this thread.
unsafe fn first_hardware_encoder() -> Result<Option<IMFActivate>, EncodeError> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let mut list: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut count = 0u32;
    // SAFETY: the out pointers are live locals; the returned array is read
    // within `count` and freed with CoTaskMemFree after its entries are moved out.
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&input),
            Some(&output),
            &mut list,
            &mut count,
        )?;
        if list.is_null() {
            return Ok(None);
        }
        let entries = std::slice::from_raw_parts_mut(list, count as usize);
        let first = entries.first_mut().and_then(Option::take);
        for entry in entries.iter_mut() {
            drop(entry.take());
        }
        CoTaskMemFree(Some(list as *const _));
        Ok(first)
    }
}

/// Activates the encoder and configures it; returns the transform and its name.
///
/// # Safety
///
/// Media Foundation must be started on this thread.
unsafe fn open(
    activate: &IMFActivate,
    width: u32,
    height: u32,
    bitrate_bps: u64,
    fps: u32,
) -> Result<(IMFTransform, String), EncodeError> {
    // SAFETY: COM calls on owned objects; the name string is freed after copying.
    unsafe {
        let name = friendly_name(activate);
        let transform: IMFTransform = activate.ActivateObject()?;
        let attributes = transform.GetAttributes()?;
        attributes.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1)?;
        let _ = attributes.SetUINT32(&MF_LOW_LATENCY, 1);

        let codec = transform.cast::<ICodecAPI>()?;
        let bps = bitrate_bps.min(u64::from(u32::MAX)) as u32;
        let _ = codec.SetValue(
            &CODECAPI_AVEncCommonRateControlMode,
            &VARIANT::from(eAVEncCommonRateControlMode_CBR.0 as u32),
        );
        let _ = codec.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &VARIANT::from(bps));
        let _ = codec.SetValue(&CODECAPI_AVLowLatencyMode, &VARIANT::from(true));
        let _ = codec.SetValue(&CODECAPI_AVEncMPVDefaultBPictureCount, &VARIANT::from(0u32));
        let _ = codec.SetValue(&CODECAPI_AVEncMPVGOPSize, &VARIANT::from(fps * 10));

        let output = video_type(&MFVideoFormat_H264, width, height, fps)?;
        output.SetUINT32(&MF_MT_AVG_BITRATE, bps)?;
        output.SetUINT32(&MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Base.0 as u32)?;
        transform.SetOutputType(0, &output, 0)?;
        let input = video_type(&MFVideoFormat_NV12, width, height, fps)?;
        transform.SetInputType(0, &input, 0)?;

        transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
        transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
        Ok((transform, name))
    }
}

/// Builds a progressive video media type of `subtype`, size and frame rate.
///
/// # Safety
///
/// Media Foundation must be started on this thread.
unsafe fn video_type(subtype: &GUID, width: u32, height: u32, fps: u32) -> Result<IMFMediaType, EncodeError> {
    // SAFETY: COM calls on a media type this function owns.
    unsafe {
        let ty = MFCreateMediaType()?;
        ty.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        ty.SetGUID(&MF_MT_SUBTYPE, subtype)?;
        ty.SetUINT64(&MF_MT_FRAME_SIZE, (u64::from(width) << 32) | u64::from(height))?;
        ty.SetUINT64(&MF_MT_FRAME_RATE, (u64::from(fps) << 32) | 1)?;
        ty.SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
        Ok(ty)
    }
}

/// Returns the encoder's friendly name, or "hardware H.264 encoder" when it has none.
///
/// # Safety
///
/// `activate` must be a live activation object.
unsafe fn friendly_name(activate: &IMFActivate) -> String {
    let mut ptr = PWSTR::null();
    let mut len = 0;
    // SAFETY: the string Media Foundation allocates is copied, then freed once.
    unsafe {
        if activate
            .GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut ptr, &mut len)
            .is_err()
            || ptr.is_null()
        {
            return "hardware H.264 encoder".into();
        }
        let name = ptr.to_string().unwrap_or_default();
        CoTaskMemFree(Some(ptr.0 as *const _));
        name
    }
}
