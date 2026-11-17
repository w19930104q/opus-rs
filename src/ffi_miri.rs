//! Miri-only stand-in for the `opusic_sys` FFI crate.
//!
//! Miri cannot execute the machine code produced by building the real C
//! library, so when the crate is compiled under Miri (`cfg(miri)`) this module
//! is substituted for `opusic_sys` via the `ffi` alias in `lib.rs`. It exposes
//! the *same* constants, opaque types and function signatures, backed by a
//! small pure-Rust model of Opus packet framing.
//!
//! The goal is not to reproduce the codec — there is no audio processing — but
//! to let all of the *safe* hardening logic run under Miri: length/`c_int`
//! conversions, the `parse` frame-containment checks, repacketizer ownership
//! and the borrowed lifetimes. The framing model deliberately mirrors the
//! parts of libopus's behavior that the tests rely on.

#![allow(clippy::missing_safety_doc, dead_code, unused_unsafe)]

use std::ffi::{c_char, c_int, c_uchar};

// ----------------------------------------------------------------------------
// Constants (values match opusic-sys / libopus 1.6).

pub const OPUS_OK: c_int = 0;
pub const OPUS_BAD_ARG: c_int = -1;
pub const OPUS_BUFFER_TOO_SMALL: c_int = -2;
pub const OPUS_INTERNAL_ERROR: c_int = -3;
pub const OPUS_INVALID_PACKET: c_int = -4;
pub const OPUS_UNIMPLEMENTED: c_int = -5;
pub const OPUS_INVALID_STATE: c_int = -6;
pub const OPUS_ALLOC_FAIL: c_int = -7;

pub const OPUS_AUTO: c_int = -1000;
pub const OPUS_BITRATE_MAX: c_int = -1;

pub const OPUS_APPLICATION_VOIP: c_int = 2048;
pub const OPUS_APPLICATION_AUDIO: c_int = 2049;
pub const OPUS_APPLICATION_RESTRICTED_LOWDELAY: c_int = 2051;

pub const OPUS_SIGNAL_VOICE: c_int = 3001;
pub const OPUS_SIGNAL_MUSIC: c_int = 3002;

pub const OPUS_BANDWIDTH_NARROWBAND: c_int = 1101;
pub const OPUS_BANDWIDTH_MEDIUMBAND: c_int = 1102;
pub const OPUS_BANDWIDTH_WIDEBAND: c_int = 1103;
pub const OPUS_BANDWIDTH_SUPERWIDEBAND: c_int = 1104;
pub const OPUS_BANDWIDTH_FULLBAND: c_int = 1105;

pub const OPUS_FRAMESIZE_ARG: c_int = 5000;
pub const OPUS_FRAMESIZE_2_5_MS: c_int = 5001;
pub const OPUS_FRAMESIZE_5_MS: c_int = 5002;
pub const OPUS_FRAMESIZE_10_MS: c_int = 5003;
pub const OPUS_FRAMESIZE_20_MS: c_int = 5004;
pub const OPUS_FRAMESIZE_40_MS: c_int = 5005;
pub const OPUS_FRAMESIZE_60_MS: c_int = 5006;
pub const OPUS_FRAMESIZE_80_MS: c_int = 5007;
pub const OPUS_FRAMESIZE_100_MS: c_int = 5008;
pub const OPUS_FRAMESIZE_120_MS: c_int = 5009;

macro_rules! ctl_requests {
	($($name:ident = $val:literal;)*) => {
		$(pub const $name: c_int = $val;)*
	};
}
ctl_requests! {
	OPUS_SET_APPLICATION_REQUEST = 4000;
	OPUS_GET_APPLICATION_REQUEST = 4001;
	OPUS_SET_BITRATE_REQUEST = 4002;
	OPUS_GET_BITRATE_REQUEST = 4003;
	OPUS_SET_MAX_BANDWIDTH_REQUEST = 4004;
	OPUS_GET_MAX_BANDWIDTH_REQUEST = 4005;
	OPUS_SET_VBR_REQUEST = 4006;
	OPUS_GET_VBR_REQUEST = 4007;
	OPUS_SET_BANDWIDTH_REQUEST = 4008;
	OPUS_GET_BANDWIDTH_REQUEST = 4009;
	OPUS_SET_COMPLEXITY_REQUEST = 4010;
	OPUS_GET_COMPLEXITY_REQUEST = 4011;
	OPUS_SET_INBAND_FEC_REQUEST = 4012;
	OPUS_GET_INBAND_FEC_REQUEST = 4013;
	OPUS_SET_PACKET_LOSS_PERC_REQUEST = 4014;
	OPUS_GET_PACKET_LOSS_PERC_REQUEST = 4015;
	OPUS_SET_DTX_REQUEST = 4016;
	OPUS_GET_DTX_REQUEST = 4017;
	OPUS_SET_VBR_CONSTRAINT_REQUEST = 4020;
	OPUS_GET_VBR_CONSTRAINT_REQUEST = 4021;
	OPUS_SET_FORCE_CHANNELS_REQUEST = 4022;
	OPUS_GET_FORCE_CHANNELS_REQUEST = 4023;
	OPUS_SET_SIGNAL_REQUEST = 4024;
	OPUS_GET_SIGNAL_REQUEST = 4025;
	OPUS_GET_LOOKAHEAD_REQUEST = 4027;
	OPUS_GET_SAMPLE_RATE_REQUEST = 4029;
	OPUS_GET_FINAL_RANGE_REQUEST = 4031;
	OPUS_GET_PITCH_REQUEST = 4033;
	OPUS_SET_GAIN_REQUEST = 4034;
	OPUS_GET_GAIN_REQUEST = 4045;
	OPUS_SET_LSB_DEPTH_REQUEST = 4036;
	OPUS_GET_LSB_DEPTH_REQUEST = 4037;
	OPUS_GET_LAST_PACKET_DURATION_REQUEST = 4039;
	OPUS_SET_EXPERT_FRAME_DURATION_REQUEST = 4040;
	OPUS_GET_EXPERT_FRAME_DURATION_REQUEST = 4041;
	OPUS_SET_PREDICTION_DISABLED_REQUEST = 4042;
	OPUS_GET_PREDICTION_DISABLED_REQUEST = 4043;
	OPUS_SET_PHASE_INVERSION_DISABLED_REQUEST = 4046;
	OPUS_GET_PHASE_INVERSION_DISABLED_REQUEST = 4047;
	OPUS_GET_IN_DTX_REQUEST = 4049;
	OPUS_RESET_STATE = 5032;
}

// ----------------------------------------------------------------------------
// Opaque handle types. The real types are zero-sized opaque enums in the
// bindgen output; we back ours with a state struct allocated on the heap so
// the mock can remember things between calls, while keeping the public layout
// opaque to the wrapper exactly as in the real FFI.

#[repr(C)]
pub struct OpusEncoder {
	pub sample_rate: i32,
	pub channels: i32,
}

#[repr(C)]
pub struct OpusDecoder {
	pub sample_rate: i32,
	pub channels: i32,
	pub last_packet_duration: i32,
}

#[repr(C)]
pub struct OpusMSEncoder {
	pub channels: i32,
}

#[repr(C)]
pub struct OpusMSDecoder {
	pub channels: i32,
}

/// One frame retained by the mock repacketizer: a pointer/length pair into the
/// caller's packet, exactly like the real struct keeps pointers into the data
/// handed to `opus_repacketizer_cat`.
#[repr(C)]
pub struct OpusRepacketizer {
	pub toc: u8,
	pub count: i32,
	pub frames: [(*const c_uchar, i16); 48],
}

const NULL_FRAME: (*const c_uchar, i16) = (std::ptr::null(), 0);

// ----------------------------------------------------------------------------
// Version / strings

static VERSION: &[u8] = b"mock-opus-1.6\0";

pub fn opus_get_version_string() -> *const c_char {
	VERSION.as_ptr() as *const c_char
}

pub fn opus_strerror(code: c_int) -> *const c_char {
	let text: &[u8] = match code {
		OPUS_OK => b"success\0",
		OPUS_BAD_ARG => b"bad argument\0",
		OPUS_BUFFER_TOO_SMALL => b"buffer too small\0",
		OPUS_INTERNAL_ERROR => b"internal error\0",
		OPUS_INVALID_PACKET => b"invalid packet\0",
		OPUS_UNIMPLEMENTED => b"unimplemented\0",
		OPUS_INVALID_STATE => b"invalid state\0",
		OPUS_ALLOC_FAIL => b"allocation failed\0",
		_ => b"unknown error\0",
	};
	text.as_ptr() as *const c_char
}

// ----------------------------------------------------------------------------
// Framing model
//
// Only the frame *layout* is modeled, enough for packet analysis, parse and
// the repacketizer. It supports the three TOC code classes:
//   code 0: one frame occupying the whole payload;
//   code 1: two equal-length CBR frames;
//   code 2: VBR, a one-byte frame count followed by per-frame lengths;
//   code 3: like code 2 with a self-delimiting length byte.

/// Number of frames implied by a TOC byte and buffer length.
fn frame_count(data: &[u8]) -> c_int {
	if data.is_empty() {
		return OPUS_BAD_ARG;
	}
	match data[0] & 0x3 {
		0 => 1,
		1 => 2,
		2 | 3 => {
			if data.len() < 2 {
				return OPUS_INVALID_PACKET;
			}
			let count = data[1] & 0x3F;
			if count == 0 {
				// count of 0 encodes 48 frames per the Opus spec.
				48
			} else {
				count as c_int
			}
		}
		_ => unreachable!(),
	}
}

/// Validate that `data` holds a frame of exactly `frame_size` samples per the
/// TOC config. The mock treats any non-empty payload as a valid frame and
/// rejects empty packets or framing inconsistencies, mirroring libopus's
/// structural (not acoustic) checks.
fn parse_into<'a>(
	data: &'a [u8],
	frames: &mut [*const c_uchar; 48],
	sizes: &mut [i16; 48],
	payload_offset: &mut c_int,
) -> c_int {
	if data.is_empty() {
		return OPUS_INVALID_PACKET;
	}
	let count = frame_count(data);
	if count < 0 {
		return count;
	}
	let count = count as usize;
	if count > 48 {
		return OPUS_INVALID_PACKET;
	}
	let base = data.as_ptr();
	match data[0] & 0x3 {
		0 => {
			let size = data.len() - 1;
			if size == 0 {
				return OPUS_INVALID_PACKET;
			}
			frames[0] = unsafe { base.add(1) };
			sizes[0] = size as i16;
			*payload_offset = 1;
		}
		1 => {
			let payload = data.len() - 1;
			if payload < 2 || payload % 2 != 0 {
				return OPUS_INVALID_PACKET;
			}
			let half = (payload / 2) as i16;
			frames[0] = unsafe { base.add(1) };
			sizes[0] = half;
			frames[1] = unsafe { base.add(1 + half as usize) };
			sizes[1] = half;
			*payload_offset = 1;
		}
		_ => {
			// VBR framing: data[1] is the count byte, then count-1 length
			// bytes, then the frames themselves.
			if data.len() < 2 {
				return OPUS_INVALID_PACKET;
			}
			let mut cursor = 2usize;
			let mut offsets = [0usize; 48];
			for i in 0..count {
				offsets[i] = cursor;
				if i + 1 < count {
					if cursor >= data.len() {
						return OPUS_INVALID_PACKET;
					}
					cursor += 1; // one length byte per non-final frame
				}
			}
			// The final frame takes whatever payload remains.
			if cursor > data.len() {
				return OPUS_INVALID_PACKET;
			}
			for i in 0..count {
				let next = if i + 1 < count { offsets[i + 1] } else { data.len() };
				if next < offsets[i] {
					return OPUS_INVALID_PACKET;
				}
				let size = next - offsets[i];
				if size == 0 || size > i16::MAX as usize {
					return OPUS_INVALID_PACKET;
				}
				frames[i] = unsafe { base.add(offsets[i]) };
				sizes[i] = size as i16;
			}
			*payload_offset = 2;
		}
	}
	count as c_int
}

// ----------------------------------------------------------------------------
// Packet analysis

pub fn opus_packet_get_bandwidth(data: *const c_uchar) -> c_int {
	if data.is_null() {
		return OPUS_BAD_ARG;
	}
	// Encode a plausible bandwidth from the TOC config, always a defined value.
	let toc = unsafe { data.read() };
	match (toc >> 3) & 0xF {
		0..=3 => OPUS_BANDWIDTH_NARROWBAND,
		4..=7 => OPUS_BANDWIDTH_WIDEBAND,
		8..=11 => OPUS_BANDWIDTH_SUPERWIDEBAND,
		_ => OPUS_BANDWIDTH_FULLBAND,
	}
}

pub fn opus_packet_get_nb_channels(data: *const c_uchar) -> c_int {
	if data.is_null() {
		return OPUS_BAD_ARG;
	}
	if unsafe { data.read() } & 0x4 != 0 {
		2
	} else {
		1
	}
}

pub fn opus_packet_get_samples_per_frame(data: *const c_uchar, _fs: c_int) -> c_int {
	if data.is_null() {
		return OPUS_BAD_ARG;
	}
	// Config 0..3 are SILK-only with 10/20/40/60 ms frame sizes; everything
	// else uses a 20 ms CELT/Hybrid frame. The mock only needs a positive,
	// bounded number, so map config to one of the standard 48k sizes.
	match unsafe { data.read() } >> 3 & 0xF {
		0 => 480,
		1 => 960,
		2 => 1920,
		3 => 2880,
		_ => 960,
	}
}

pub fn opus_packet_get_nb_frames(packet: *const c_uchar, len: c_int) -> c_int {
	if len < 1 || packet.is_null() {
		return OPUS_BAD_ARG;
	}
	let data = unsafe { std::slice::from_raw_parts(packet, len as usize) };
	frame_count(data)
}

pub fn opus_packet_get_nb_samples(packet: *const c_uchar, len: c_int, fs: c_int) -> c_int {
	if len < 1 || packet.is_null() {
		return OPUS_BAD_ARG;
	}
	let data = unsafe { std::slice::from_raw_parts(packet, len as usize) };
	let count = frame_count(data);
	if count < 0 {
		return count;
	}
	let per_frame = opus_packet_get_samples_per_frame(packet, fs);
	if per_frame < 0 {
		return per_frame;
	}
	per_frame * count
}

pub fn opus_packet_parse(
	data: *const c_uchar,
	len: c_int,
	out_toc: *mut c_uchar,
	frames: *mut *const c_uchar,
	size: *mut i16,
	payload_offset: *mut c_int,
) -> c_int {
	if len < 0 || data.is_null() {
		return OPUS_BAD_ARG;
	}
	if len == 0 {
		return OPUS_INVALID_PACKET;
	}
	let packet = unsafe { std::slice::from_raw_parts(data, len as usize) };
	unsafe { out_toc.write(packet[0]) };
	let mut frame_arr = [std::ptr::null(); 48];
	let mut size_arr = [0i16; 48];
	let mut offset = 0;
	let result = parse_into(packet, &mut frame_arr, &mut size_arr, &mut offset);
	if result < 0 {
		return result;
	}
	for i in 0..result as usize {
		unsafe {
			frames.add(i).write(frame_arr[i]);
			size.add(i).write(size_arr[i]);
		}
	}
	unsafe { payload_offset.write(offset) };
	result
}

// ----------------------------------------------------------------------------
// Padding

pub fn opus_packet_pad(data: *mut c_uchar, len: c_int, new_len: c_int) -> c_int {
	if len < 1 {
		return OPUS_BAD_ARG;
	}
	if len == new_len {
		return OPUS_OK;
	}
	if len > new_len {
		return OPUS_BAD_ARG;
	}
	// Validate the existing packet before padding.
	let packet = unsafe { std::slice::from_raw_parts(data, len as usize) };
	let count = frame_count(packet);
	if count < 0 {
		return count;
	}
	// Fill the added region with zero padding, as libopus does.
	for i in len..new_len {
		unsafe { data.add(i as usize).write(0) };
	}
	OPUS_OK
}

pub fn opus_packet_unpad(data: *mut c_uchar, len: c_int) -> c_int {
	if len < 1 {
		return OPUS_BAD_ARG;
	}
	let packet = unsafe { std::slice::from_raw_parts(data, len as usize) };
	let count = frame_count(packet);
	if count < 0 {
		return count;
	}
	// Without real padding bookkeeping the mock reports the original length.
	len
}

pub fn opus_multistream_packet_pad(
	data: *mut c_uchar,
	len: c_int,
	new_len: c_int,
	_nb_streams: c_int,
) -> c_int {
	opus_packet_pad(data, len, new_len)
}

pub fn opus_multistream_packet_unpad(data: *mut c_uchar, len: c_int, _nb_streams: c_int) -> c_int {
	opus_packet_unpad(data, len)
}

// ----------------------------------------------------------------------------
// Repacketizer

pub fn opus_repacketizer_get_size() -> c_int {
	std::mem::size_of::<OpusRepacketizer>() as c_int
}

pub fn opus_repacketizer_create() -> *mut OpusRepacketizer {
	Box::into_raw(Box::new(OpusRepacketizer { toc: 0, count: 0, frames: [NULL_FRAME; 48] }))
}

pub fn opus_repacketizer_init(rp: *mut OpusRepacketizer) -> *mut OpusRepacketizer {
	if !rp.is_null() {
		unsafe {
			(*rp).count = 0;
			(*rp).toc = 0;
		}
	}
	rp
}

pub fn opus_repacketizer_destroy(rp: *mut OpusRepacketizer) {
	if !rp.is_null() {
		unsafe { drop(Box::from_raw(rp)) };
	}
}

pub fn opus_repacketizer_get_nb_frames(rp: *mut OpusRepacketizer) -> c_int {
	if rp.is_null() {
		return 0;
	}
	unsafe { (*rp).count }
}

pub fn opus_repacketizer_cat(rp: *mut OpusRepacketizer, data: *const c_uchar, len: c_int) -> c_int {
	if rp.is_null() || len < 1 || data.is_null() {
		return OPUS_INVALID_PACKET;
	}
	let packet = unsafe { std::slice::from_raw_parts(data, len as usize) };
	let mut frame_arr = [std::ptr::null(); 48];
	let mut size_arr = [0i16; 48];
	let mut offset = 0;
	let added = parse_into(packet, &mut frame_arr, &mut size_arr, &mut offset);
	if added < 0 {
		return added;
	}
	let rp = unsafe { &mut *rp };
	let toc = packet[0];
	if rp.count == 0 {
		rp.toc = toc;
	} else if (rp.toc & 0xFC) != (toc & 0xFC) {
		return OPUS_INVALID_PACKET;
	}
	if rp.count as usize + added as usize > 48 {
		return OPUS_INVALID_PACKET;
	}
	for i in 0..added as usize {
		let dst = rp.count as usize + i;
		rp.frames[dst] = (frame_arr[i], size_arr[i]);
	}
	rp.count += added;
	OPUS_OK
}

/// Serialize the retained frames back into `data`, returning the total length
/// or OPUS_BUFFER_TOO_SMALL. Mirrors libopus's buffer accounting.
fn out_frames(rp: &OpusRepacketizer, data: *mut c_uchar, maxlen: c_int) -> c_int {
	let count = rp.count as usize;
	if count == 0 {
		return OPUS_BAD_ARG;
	}
	let total: usize = rp.frames[..count].iter().map(|(_, s)| *s as usize).sum::<usize>()
		+ 1 // TOC
		+ count.saturating_sub(1); // one length byte per non-final frame
	if (total as i64) > maxlen as i64 {
		return OPUS_BUFFER_TOO_SMALL;
	}
	unsafe {
		data.write(rp.toc);
		let mut cursor = 1usize;
		if count > 1 {
			// VBR code 2 packet with an explicit count byte.
			data.add(1).write(if count == 48 { 0 } else { count as u8 });
			cursor = 2;
		}
		for i in 0..count {
			let (ptr, size) = rp.frames[i];
			let size = size as usize;
			std::ptr::copy_nonoverlapping(ptr, data.add(cursor), size);
			cursor += size;
		}
	}
	total as c_int
}

pub fn opus_repacketizer_out(
	rp: *mut OpusRepacketizer,
	data: *mut c_uchar,
	maxlen: c_int,
) -> c_int {
	if rp.is_null() {
		return OPUS_BAD_ARG;
	}
	out_frames(unsafe { &*rp }, data, maxlen)
}

pub fn opus_repacketizer_out_range(
	rp: *mut OpusRepacketizer,
	begin: c_int,
	end: c_int,
	data: *mut c_uchar,
	maxlen: c_int,
) -> c_int {
	if rp.is_null() {
		return OPUS_BAD_ARG;
	}
	let rp = unsafe { &*rp };
	if begin < 0 || begin >= end || end > rp.count {
		return OPUS_BAD_ARG;
	}
	// Build a temporary view restricted to [begin, end) and reuse out_frames.
	let mut view = OpusRepacketizer {
		toc: rp.toc,
		count: end - begin,
		frames: [NULL_FRAME; 48],
	};
	for i in 0..(end - begin) as usize {
		view.frames[i] = rp.frames[begin as usize + i];
	}
	out_frames(&view, data, maxlen)
}

// ----------------------------------------------------------------------------
// Encoder / decoder handles: construction and no-op CTLs. The mock performs no
// audio work; encode/decode return a deterministic positive length so the
// wrapper's success paths and ownership/drop logic are still exercised.

pub fn opus_encoder_create(
	_fs: c_int,
	channels: c_int,
	_application: c_int,
	error: *mut c_int,
) -> *mut OpusEncoder {
	if channels != 1 && channels != 2 {
		unsafe { error.write(OPUS_BAD_ARG) };
		return std::ptr::null_mut();
	}
	unsafe { error.write(OPUS_OK) };
	Box::into_raw(Box::new(OpusEncoder { sample_rate: _fs, channels }))
}

pub fn opus_encoder_destroy(st: *mut OpusEncoder) {
	if !st.is_null() {
		unsafe { drop(Box::from_raw(st)) };
	}
}

pub fn opus_decoder_create(_fs: c_int, channels: c_int, error: *mut c_int) -> *mut OpusDecoder {
	if channels != 1 && channels != 2 {
		unsafe { error.write(OPUS_BAD_ARG) };
		return std::ptr::null_mut();
	}
	unsafe { error.write(OPUS_OK) };
	Box::into_raw(Box::new(OpusDecoder {
		sample_rate: _fs,
		channels,
		last_packet_duration: 0,
	}))
}

pub fn opus_decoder_destroy(st: *mut OpusDecoder) {
	if !st.is_null() {
		unsafe { drop(Box::from_raw(st)) };
	}
}

pub fn opus_multistream_encoder_create(
	_fs: c_int,
	channels: c_int,
	_streams: c_int,
	_coupled: c_int,
	_mapping: *const c_uchar,
	_application: c_int,
	error: *mut c_int,
) -> *mut OpusMSEncoder {
	if channels < 1 {
		unsafe { error.write(OPUS_BAD_ARG) };
		return std::ptr::null_mut();
	}
	unsafe { error.write(OPUS_OK) };
	Box::into_raw(Box::new(OpusMSEncoder { channels }))
}

pub fn opus_multistream_encoder_destroy(st: *mut OpusMSEncoder) {
	if !st.is_null() {
		unsafe { drop(Box::from_raw(st)) };
	}
}

pub fn opus_multistream_decoder_create(
	_fs: c_int,
	channels: c_int,
	_streams: c_int,
	_coupled: c_int,
	_mapping: *const c_uchar,
	error: *mut c_int,
) -> *mut OpusMSDecoder {
	if channels < 1 {
		unsafe { error.write(OPUS_BAD_ARG) };
		return std::ptr::null_mut();
	}
	unsafe { error.write(OPUS_OK) };
	Box::into_raw(Box::new(OpusMSDecoder { channels }))
}

pub fn opus_multistream_decoder_destroy(st: *mut OpusMSDecoder) {
	if !st.is_null() {
		unsafe { drop(Box::from_raw(st)) };
	}
}

// Encode/decode return a frame size without touching the audio buffers beyond
// reading their lengths, which the wrapper supplies. Empty input (packet loss)
// is accepted the same way the real decoder accepts a null packet.
pub fn opus_encode(
	_st: *mut OpusEncoder,
	_pcm: *const i16,
	frame_size: c_int,
	_data: *mut c_uchar,
	max_len: c_int,
) -> c_int {
	if max_len < 1 || frame_size < 0 {
		return OPUS_BAD_ARG;
	}
	// Pretend to emit a small fixed packet.
	let produced = 3.min(max_len);
	produced
}

pub fn opus_encode_float(
	st: *mut OpusEncoder,
	pcm: *const f32,
	frame_size: c_int,
	data: *mut c_uchar,
	max_len: c_int,
) -> c_int {
	opus_encode(st, pcm as *const i16, frame_size, data, max_len)
}

pub fn opus_decode(
	st: *mut OpusDecoder,
	_data: *const c_uchar,
	len: c_int,
	_out: *mut i16,
	frame_size: c_int,
	_fec: c_int,
) -> c_int {
	if st.is_null() || frame_size < 0 {
		return OPUS_BAD_ARG;
	}
	if len == 0 {
		// Packet-loss concealment: report the requested frame size.
		return frame_size;
	}
	// A non-empty corrupt packet is rejected to exercise error mapping.
	OPUS_INVALID_PACKET
}

pub fn opus_decode_float(
	st: *mut OpusDecoder,
	data: *const c_uchar,
	len: c_int,
	out: *mut f32,
	frame_size: c_int,
	fec: c_int,
) -> c_int {
	opus_decode(st as *mut OpusDecoder, data, len, out as *mut i16, frame_size, fec)
}

pub fn opus_decoder_get_nb_samples(
	_st: *const OpusDecoder,
	packet: *const c_uchar,
	len: c_int,
) -> c_int {
	opus_packet_get_nb_samples(packet, len, 48000)
}

pub fn opus_multistream_encode(
	st: *mut OpusMSEncoder,
	pcm: *const i16,
	frame_size: c_int,
	data: *mut c_uchar,
	max_len: c_int,
) -> c_int {
	let _ = st;
	opus_encode(std::ptr::null_mut(), pcm, frame_size, data, max_len)
}

pub fn opus_multistream_encode_float(
	st: *mut OpusMSEncoder,
	pcm: *const f32,
	frame_size: c_int,
	data: *mut c_uchar,
	max_len: c_int,
) -> c_int {
	opus_multistream_encode(st, pcm as *const i16, frame_size, data, max_len)
}

pub fn opus_multistream_decode(
	st: *mut OpusMSDecoder,
	data: *const c_uchar,
	len: c_int,
	out: *mut i16,
	frame_size: c_int,
	fec: c_int,
) -> c_int {
	let _ = st;
	opus_decode(std::ptr::null_mut(), data, len, out, frame_size, fec)
}

pub fn opus_multistream_decode_float(
	st: *mut OpusMSDecoder,
	data: *const c_uchar,
	len: c_int,
	out: *mut f32,
	frame_size: c_int,
	fec: c_int,
) -> c_int {
	opus_multistream_decode(st, data, len, out as *mut i16, frame_size, fec)
}

pub fn opus_pcm_soft_clip(_pcm: *mut f32, frame_size: c_int, channels: c_int, _mem: *mut f32) {
	// The wrapper guarantees whole-frame chunks; sanity-check the arguments so
	// Miri verifies the chunking math never produces a negative/zero overflow.
	debug_assert!(frame_size >= 0);
	debug_assert!(channels == 1 || channels == 2);
}

// Generic CTLs: acknowledge every request and echo scalar values back so the
// getter/setter round-trips succeed without modeling codec internals. The
// signatures match the variadic bindgen declarations in opusic-sys.
pub unsafe extern "C" fn opus_encoder_ctl(_st: *mut OpusEncoder, _request: c_int, _: ...) -> c_int {
	OPUS_OK
}
pub unsafe extern "C" fn opus_decoder_ctl(_st: *mut OpusDecoder, _request: c_int, _: ...) -> c_int {
	OPUS_OK
}
pub unsafe extern "C" fn opus_multistream_encoder_ctl(
	_st: *mut OpusMSEncoder,
	_request: c_int,
	_: ...
) -> c_int {
	OPUS_OK
}
pub unsafe extern "C" fn opus_multistream_decoder_ctl(
	_st: *mut OpusMSDecoder,
	_request: c_int,
	_: ...
) -> c_int {
	OPUS_OK
}
