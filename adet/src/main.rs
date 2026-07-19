//! Simple sound event detector.
//!
//! Pipeline:
//!   cpal input callback --(rtrb ring buffer)--> processing thread
//!       --(crossbeam channel)--> writer thread --> WAV file on disk
//!
//! The processing thread keeps a rolling 1s "pre-roll" buffer at all times,
//! runs a simple energy-based detector, and drives a state machine that
//! captures: 1s before the event + up to 10s of the event itself + 2s after,
//! for a hard cap of 13s per recording.
//!
//! This is a reference implementation: tune the detector thresholds for your
//! mic/environment, and swap `EnergyDetector` for something smarter (e.g. a
//! small VAD/classifier) if energy thresholding isn't good enough.

use anyhow::{Context, Result};
use chrono::Local;
use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
use crossbeam_channel::{bounded, Sender};
use rtrb::RingBuffer;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------

const PRE_ROLL_SECS: f32 = 1.0;
const MAX_EVENT_SECS: f32 = 10.0;
const POST_ROLL_SECS: f32 = 2.0;

/// Frame size used for RMS/energy detection, in milliseconds.
const DETECT_FRAME_MS: f32 = 20.0;

/// Detector thresholds (tune for your mic / environment / gain staging).
/// These are RMS values on a [-1.0, 1.0] float sample scale.
const THRESHOLD_ON: f32 = 0.06;
const THRESHOLD_OFF: f32 = 0.03;
/// Consecutive "loud" frames required before declaring an onset (debounce).
const ON_DEBOUNCE_FRAMES: usize = 2;
/// Consecutive "quiet" frames required before declaring an offset (hangover,
/// keeps brief dips inside a sound from ending the event early).
const OFF_HANGOVER_FRAMES: usize = 15; // ~300ms at 20ms frames

const OUTPUT_DIR: &str = "recordings";

// ---------------------------------------------------------------------
// Circular pre-roll buffer
// ---------------------------------------------------------------------

/// Fixed-capacity circular buffer of interleaved f32 samples. Always being
/// overwritten; `snapshot()` returns the last `capacity` samples in
/// chronological order without disturbing the buffer.
struct CircularBuffer {
    buf: Vec<f32>,
    capacity: usize,
    write_pos: usize,
    filled: bool,
}

impl CircularBuffer {
    fn new(capacity: usize) -> Self {
        Self {
            buf: vec![0.0; capacity],
            capacity,
            write_pos: 0,
            filled: false,
        }
    }

    fn push_slice(&mut self, samples: &[f32]) {
        for &s in samples {
            self.buf[self.write_pos] = s;
            self.write_pos = (self.write_pos + 1) % self.capacity;
            if self.write_pos == 0 {
                self.filled = true;
            }
        }
    }

    /// Returns the buffered samples in chronological order (oldest first).
    fn snapshot(&self) -> Vec<f32> {
        if !self.filled {
            self.buf[..self.write_pos].to_vec()
        } else {
            let mut out = Vec::with_capacity(self.capacity);
            out.extend_from_slice(&self.buf[self.write_pos..]);
            out.extend_from_slice(&self.buf[..self.write_pos]);
            out
        }
    }
}

// ---------------------------------------------------------------------
// Detector
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectorEvent {
    Onset,
    Offset,
    None,
}

/// Simple RMS-threshold detector with hysteresis + debounce/hangover.
/// Swap this out for a smarter model later; it only needs to implement
/// `process_frame`.
struct EnergyDetector {
    active: bool,
    on_run: usize,
    off_run: usize,
}

impl EnergyDetector {
    fn new() -> Self {
        Self {
            active: false,
            on_run: 0,
            off_run: 0,
        }
    }

    /// Feed one detection frame (mono-mixed) worth of samples, get back
    /// whether this frame caused an onset/offset transition.
    fn process_frame(&mut self, frame: &[f32]) -> DetectorEvent {
        let rms = rms(frame);

        if !self.active {
            if rms >= THRESHOLD_ON {
                self.on_run += 1;
                self.off_run = 0;
                if self.on_run >= ON_DEBOUNCE_FRAMES {
                    self.active = true;
                    self.on_run = 0;
                    return DetectorEvent::Onset;
                }
            } else {
                self.on_run = 0;
            }
        } else {
            if rms < THRESHOLD_OFF {
                self.off_run += 1;
                if self.off_run >= OFF_HANGOVER_FRAMES {
                    self.active = false;
                    self.off_run = 0;
                    return DetectorEvent::Offset;
                }
            } else {
                self.off_run = 0;
            }
        }
        DetectorEvent::None
    }
}

fn rms(samples: &[f32]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let sum_sq: f32 = samples.iter().map(|s| s * s).sum();
    (sum_sq / samples.len() as f32).sqrt()
}

// ---------------------------------------------------------------------
// Recording state machine
// ---------------------------------------------------------------------

enum RecState {
    Idle,
    Recording { event_frames_captured: usize },
    PostRoll { post_frames_captured: usize },
}

struct RecordingJob {
    samples: Vec<f32>,
    channels: u16,
    sample_rate: u32,
}

struct Pipeline {
    channels: u16,
    sample_rate: u32,
    detect_frame_len_samples: usize, // interleaved sample count per detect frame
    max_event_frames: usize,         // in detect-frame units
    post_roll_frames: usize,         // in detect-frame units
    pre_roll: CircularBuffer,
    detector: EnergyDetector,
    state: RecState,
    current: Vec<f32>,
    writer_tx: Sender<RecordingJob>,
}

impl Pipeline {
    fn new(channels: u16, sample_rate: u32, writer_tx: Sender<RecordingJob>) -> Self {
        let detect_frame_len_frames = ((sample_rate as f32) * (DETECT_FRAME_MS / 1000.0)) as usize;
        let detect_frame_len_samples = detect_frame_len_frames * channels as usize;
        let pre_roll_samples = ((sample_rate as f32) * PRE_ROLL_SECS) as usize * channels as usize;

        Self {
            channels,
            sample_rate,
            detect_frame_len_samples,
            max_event_frames: ((MAX_EVENT_SECS * 1000.0) / DETECT_FRAME_MS) as usize,
            post_roll_frames: ((POST_ROLL_SECS * 1000.0) / DETECT_FRAME_MS) as usize,
            pre_roll: CircularBuffer::new(pre_roll_samples),
            detector: EnergyDetector::new(),
            state: RecState::Idle,
            current: Vec::new(),
            writer_tx,
        }
    }

    /// Call with one detect-sized block of interleaved samples.
    fn process_block(&mut self, block: &[f32]) {
        // Always keep the pre-roll buffer current.
        self.pre_roll.push_slice(block);

        // Mix down to mono just for detection (cheap, doesn't affect what's saved).
        let mono_frame = mono_mix(block, self.channels as usize);
        let evt = self.detector.process_frame(&mono_frame);

        match self.state {
            RecState::Idle => {
                if evt == DetectorEvent::Onset {
                    log::info!("Event onset detected");
                    self.current = self.pre_roll.snapshot();
                    self.current.extend_from_slice(block);
                    self.state = RecState::Recording {
                        event_frames_captured: 1,
                    };
                }
            }
            RecState::Recording {
                ref mut event_frames_captured,
            } => {
                self.current.extend_from_slice(block);
                *event_frames_captured += 1;

                let hit_cap = *event_frames_captured >= self.max_event_frames;
                if hit_cap {
                    log::warn!("Event exceeded {}s cap, cutting short", MAX_EVENT_SECS);
                }

                if evt == DetectorEvent::Offset || hit_cap {
                    self.state = RecState::PostRoll {
                        post_frames_captured: 0,
                    };
                }
            }
            RecState::PostRoll {
                ref mut post_frames_captured,
            } => {
                self.current.extend_from_slice(block);
                *post_frames_captured += 1;

                if *post_frames_captured >= self.post_roll_frames {
                    log::info!(
                        "Recording complete: {:.2}s",
                        self.current.len() as f32
                            / self.channels as f32
                            / self.sample_rate as f32
                    );
                    let job = RecordingJob {
                        samples: std::mem::take(&mut self.current),
                        channels: self.channels,
                        sample_rate: self.sample_rate,
                    };
                    if self.writer_tx.send(job).is_err() {
                        log::error!("Writer thread gone, dropping recording");
                    }
                    self.state = RecState::Idle;
                }
            }
        }
    }

    /// Called on shutdown. If a recording is currently in progress (mid
    /// event or mid post-roll), save whatever has been captured so far
    /// rather than throwing it away. This intentionally does NOT pad the
    /// post-roll out to the full 2s — we just stop where we are.
    fn finalize_partial(&mut self) {
        if matches!(self.state, RecState::Idle) {
            return;
        }
        log::info!(
            "Shutdown mid-recording, flushing partial clip ({:.2}s captured)",
            self.current.len() as f32 / self.channels as f32 / self.sample_rate as f32
        );
        let job = RecordingJob {
            samples: std::mem::take(&mut self.current),
            channels: self.channels,
            sample_rate: self.sample_rate,
        };
        if self.writer_tx.send(job).is_err() {
            log::error!("Writer thread gone, dropping partial recording");
        }
        self.state = RecState::Idle;
    }

    fn feed(&mut self, mut samples: &[f32]) {
        // Chop incoming samples (arbitrary cpal buffer sizes) into fixed
        // detect-sized blocks so RMS windows stay consistent.
        while samples.len() >= self.detect_frame_len_samples {
            let (block, rest) = samples.split_at(self.detect_frame_len_samples);
            self.process_block(block);
            samples = rest;
        }
        // Leftover partial block: for simplicity, process it as-is too
        // (slightly shorter RMS window at the boundary is harmless).
        if !samples.is_empty() {
            self.process_block(samples);
        }
    }
}

fn mono_mix(interleaved: &[f32], channels: usize) -> Vec<f32> {
    if channels <= 1 {
        return interleaved.to_vec();
    }
    interleaved
        .chunks_exact(channels)
        .map(|frame| frame.iter().sum::<f32>() / channels as f32)
        .collect()
}

// ---------------------------------------------------------------------
// Writer thread
// ---------------------------------------------------------------------

fn spawn_writer_thread(
    rx: crossbeam_channel::Receiver<RecordingJob>,
) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::fs::create_dir_all(OUTPUT_DIR).ok();
        // This loop exits naturally once every Sender<RecordingJob> is
        // dropped (i.e. once the processing thread has ended), so recv()
        // returns Err and we fall out. That's what lets main() join() this
        // thread and know all pending recordings have actually been
        // flushed to disk before the process exits.
        while let Ok(job) = rx.recv() {
            let filename = format!(
                "{}/event_{}.wav",
                OUTPUT_DIR,
                Local::now().format("%Y%m%d_%H%M%S%.3f")
            );
            if let Err(e) = write_wav(&filename, &job) {
                log::error!("Failed to write {}: {:?}", filename, e);
            } else {
                log::info!("Saved {}", filename);
                // Optional: transcode to OGG here, e.g. by shelling out to
                // `ffmpeg -i <wav> <ogg>` or using a crate like `vorbis_rs`.
            }
        }
        log::info!("Writer thread exiting (all recordings flushed)");
    })
}

fn write_wav(path: &str, job: &RecordingJob) -> Result<()> {
    let spec = hound::WavSpec {
        channels: job.channels,
        sample_rate: job.sample_rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut writer = hound::WavWriter::create(path, spec).context("creating wav writer")?;
    for &s in &job.samples {
        let clamped = s.clamp(-1.0, 1.0);
        let sample_i16 = (clamped * i16::MAX as f32) as i16;
        writer.write_sample(sample_i16)?;
    }
    writer.finalize()?;
    Ok(())
}

// ---------------------------------------------------------------------
// Audio capture (cpal) + real-time -> processing handoff
// ---------------------------------------------------------------------

fn main() -> Result<()> {
    env_logger::init();

    let host = cpal::default_host();
    let device = host
        .default_input_device()
        .context("no input device available")?;
    let config = device
        .default_input_config()
        .context("no default input config")?;

    log::info!("Using input device: {}", device.name().unwrap_or_default());
    log::info!("Config: {:?}", config);

    let sample_rate = config.sample_rate().0;
    let channels = config.channels();

    // Ring buffer between the real-time audio callback and the processing
    // thread. Capacity is generous (2s worth) so brief scheduling jitter on
    // the processing thread doesn't cause producer overflow.
    let ring_capacity = sample_rate as usize * channels as usize * 2;
    let (mut producer, mut consumer) = RingBuffer::<f32>::new(ring_capacity);

    let (writer_tx, writer_rx) = bounded::<RecordingJob>(8);
    let writer_handle = spawn_writer_thread(writer_rx);

    // Shared shutdown flag, flipped by the Ctrl+C handler below.
    let running = Arc::new(AtomicBool::new(true));
    let running_for_processing = Arc::clone(&running);

    // Processing thread: pulls from the rtrb consumer, runs detection +
    // state machine, hands finished recordings to the writer thread.
    // On shutdown it drains any samples still sitting in the ring buffer
    // and flushes an in-progress recording (if any) before exiting, so a
    // Ctrl+C doesn't silently throw away a clip that was mid-capture.
    let processing_handle = std::thread::spawn(move || {
        let mut pipeline = Pipeline::new(channels, sample_rate, writer_tx);
        let mut scratch = Vec::with_capacity(4096);
        loop {
            scratch.clear();
            while let Ok(sample) = consumer.pop() {
                scratch.push(sample);
                if scratch.len() >= 4096 {
                    break;
                }
            }

            if scratch.is_empty() {
                if !running_for_processing.load(Ordering::SeqCst) {
                    // Shutdown requested and the ring buffer is drained
                    // (the audio stream has already been stopped/dropped
                    // by main() before this flag was checked, so no more
                    // samples will arrive).
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }

            pipeline.feed(&scratch);
        }
        pipeline.finalize_partial();
        // `pipeline` (and its `writer_tx`) is dropped here, which is what
        // lets the writer thread's rx.recv() loop end.
    });

    let err_fn = |err| log::error!("Audio stream error: {}", err);

    let stream = match config.sample_format() {
        cpal::SampleFormat::F32 => device.build_input_stream(
            &config.clone().into(),
            move |data: &[f32], _| {
                // Real-time callback: push samples into the lock-free ring
                // buffer. No allocation, no blocking. If the ring buffer is
                // full (processing thread stalled), samples are dropped
                // rather than blocking the audio thread.
                for &s in data {
                    let _ = producer.push(s);
                }
            },
            err_fn,
            None,
        )?,
        other => {
            anyhow::bail!("Unsupported sample format: {:?} (extend main.rs to handle it, e.g. by converting I16/U16 to f32 before pushing)", other);
        }
    };

    stream.play()?;
    log::info!("Listening for sound events. Press Ctrl+C to stop.");

    // Ctrl+C (SIGINT) handler: just flips the shared flag. Keep this
    // handler minimal and non-blocking, as is generally recommended for
    // signal handlers.
    {
        let running = Arc::clone(&running);
        ctrlc::set_handler(move || {
            log::info!("Ctrl+C received, shutting down...");
            running.store(false, Ordering::SeqCst);
        })
        .context("failed to set Ctrl+C handler")?;
    }

    // Block the main thread until Ctrl+C flips the flag.
    while running.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(100));
    }

    // Stop feeding new audio into the pipeline before telling the
    // processing thread to wind down, so it can safely drain the ring
    // buffer to completion without racing new samples.
    stream.pause().ok();
    drop(stream);

    // Wait for the processing thread to drain remaining samples and flush
    // any in-progress recording...
    if let Err(e) = processing_handle.join() {
        log::error!("Processing thread panicked: {:?}", e);
    }
    // ...then wait for the writer thread to finish writing everything it
    // was handed, including that final partial clip.
    if let Err(e) = writer_handle.join() {
        log::error!("Writer thread panicked: {:?}", e);
    }

    log::info!("Shutdown complete.");
    Ok(())
}

#[allow(dead_code)]
fn output_path(name: &str) -> PathBuf {
    PathBuf::from(OUTPUT_DIR).join(name)
}