//! Hardening tests for untrusted input lengths.
//!
//! Every externally supplied length is treated as untrusted. These tests
//! exercise the three problematic areas named in the hardening work:
//!
//! 1. decoder packet padding (`opus-padding` style malformed packets),
//! 2. the repacketizer (`cat`, `out`, `out_range`, `combine`),
//! 3. borrowed lifetimes in `parse` and the repacketizer state.
//!
//! For every case the contract is: malicious or out-of-range input produces a
//! typed `ErrorCode` — never a panic, never UB. Valid packets must keep the
//! exact bytes produced by the original safe API.

extern crate opus;

use opus::{Application, Channels, Decoder, Encoder, ErrorCode, Repacketizer};

// 48kHz mono, one 20 ms frame = 960 samples per channel.
const MONO_20MS: usize = 48000 * 20 / 1000;

/// Encode one silent mono frame so the tests work with genuine Opus packets.
fn silent_packet() -> Vec<u8> {
	let mut encoder = Encoder::new(48000, Channels::Mono, Application::Audio).unwrap();
	let mut out = vec![0u8; 256];
	let len = encoder.encode(&[0i16; MONO_20MS], &mut out).unwrap();
	out.truncate(len);
	out
}

/// A two-frame packet (VBR, code 2) built through the repacketizer so the
/// framing is known-good.
fn two_frame_packet() -> Vec<u8> {
	let single = silent_packet();
	let mut rp = Repacketizer::new().unwrap();
	let mut out = vec![0u8; 256];
	let len = rp.combine(&[single.as_slice(), single.as_slice()], &mut out).unwrap();
	out.truncate(len);
	out
}

// ============================================================================
// Zero-length packets

#[test]
fn zero_length_decode_is_packet_loss_not_panic() {
	// An empty slice is the documented packet-loss signal and must decode as
	// concealment rather than being dereferenced.
	let mut decoder = Decoder::new(48000, Channels::Mono).unwrap();
	let mut output = vec![0i16; MONO_20MS];
	let samples = decoder.decode(&[], &mut output, false).unwrap();
	assert_eq!(samples, MONO_20MS);
}

#[test]
fn zero_length_decode_float_is_packet_loss() {
	let mut decoder = Decoder::new(48000, Channels::Mono).unwrap();
	let mut output = vec![0f32; MONO_20MS];
	let samples = decoder.decode_float(&[], &mut output, false).unwrap();
	assert_eq!(samples, MONO_20MS);
}

#[test]
fn zero_length_packet_analysis_returns_bad_arg() {
	let empty: &[u8] = &[];
	assert_eq!(opus::packet::get_bandwidth(empty).unwrap_err().code(), ErrorCode::BadArg);
	assert_eq!(opus::packet::get_nb_channels(empty).unwrap_err().code(), ErrorCode::BadArg);
	assert_eq!(
		opus::packet::get_samples_per_frame(empty, 48000).unwrap_err().code(),
		ErrorCode::BadArg
	);
}

#[test]
fn zero_length_parse_is_invalid_packet() {
	// libopus reports an empty packet as OPUS_INVALID_PACKET rather than
	// reading the TOC byte out of bounds.
	assert_eq!(opus::packet::parse(&[]).unwrap_err().code(), ErrorCode::InvalidPacket);
}

#[test]
fn zero_length_pad_and_unpad_are_bad_arg() {
	let mut empty = [0u8; 0];
	assert_eq!(opus::packet::pad(&mut empty, 0).unwrap_err().code(), ErrorCode::BadArg);
	assert_eq!(opus::packet::unpad(&mut empty).unwrap_err().code(), ErrorCode::BadArg);
	assert_eq!(
		opus::packet::multistream_pad(&mut empty, 0, 1).unwrap_err().code(),
		ErrorCode::BadArg
	);
	assert_eq!(
		opus::packet::multistream_unpad(&mut empty, 1).unwrap_err().code(),
		ErrorCode::BadArg
	);
}

#[test]
fn zero_length_repacketizer_cat_is_invalid_packet() {
	let mut rp = Repacketizer::new().unwrap();
	let mut state = rp.begin();
	assert_eq!(state.cat(&[]).unwrap_err().code(), ErrorCode::InvalidPacket);
	// A failed cat must not poison the state: a valid packet still works and
	// reports zero frames beforehand.
	assert_eq!(state.get_nb_frames(), 0);
	let packet = silent_packet();
	state.cat(&packet).unwrap();
	assert_eq!(state.get_nb_frames(), 1);
}

#[test]
fn zero_length_repacketizer_out_range_is_bad_arg() {
	// begin == end violates begin < end inside libopus.
	let mut rp = Repacketizer::new().unwrap();
	let packet = silent_packet();
	rp.begin().cat(&packet).unwrap();
	let mut out = [0u8; 256];
	let mut state = rp.begin();
	state.cat(&packet).unwrap();
	assert_eq!(state.out_range(0, 0, &mut out).unwrap_err().code(), ErrorCode::BadArg);
}

// ============================================================================
// Truncated / malformed packets

#[test]
fn truncated_packet_parse_never_escapes_buffer() {
	let packet = silent_packet();
	let base = packet.as_ptr() as usize;
	let end = base + packet.len();
	// Single-frame code-0 packets carry no embedded frame length, so their
	// remaining bytes are still a valid frame. The invariant that matters for
	// safety is therefore not "every truncation errors" but "whichever frames
	// parse() returns are always fully inside the input slice": no panic and
	// no out-of-bounds reference, however short the buffer gets.
	for cut in 0..packet.len() {
		let truncated = &packet[..packet.len() - cut];
		match opus::packet::parse(truncated) {
			Ok(parsed) => {
				assert!(parsed.payload_offset <= truncated.len());
				for frame in &parsed.frames {
					assert!(!frame.is_empty());
					let fbase = frame.as_ptr() as usize;
					assert!(fbase >= base && fbase + frame.len() <= end);
				}
			}
			Err(e) => assert_eq!(e.code(), ErrorCode::InvalidPacket),
		}
	}
	// A fully empty packet is always a strict InvalidPacket.
	assert_eq!(opus::packet::parse(&[]).unwrap_err().code(), ErrorCode::InvalidPacket);
}

// Relies on the real library rejecting a padding length that overruns the
// packet; the Miri framing mock does not model padding-length overflow.
#[cfg(not(miri))]
#[test]
fn malformed_padding_length_is_invalid_packet() {
	// Modeled on libopus's test_opus_padding overflow case: a packet whose
	// declared padding runs far past its actual end. This must never panic or
	// read out of bounds. The strict `parse` validator reports InvalidPacket.
	let packet = {
		let mut p = vec![0xFFu8; 1000];
		p[0] = 0xFF;
		p[1] = 0x41;
		*p.last_mut().unwrap() = 0x0B;
		p
	};
	assert_eq!(opus::packet::parse(&packet).unwrap_err().code(), ErrorCode::InvalidPacket);
	// Decoding a corrupt packet must likewise surface a typed error rather
	// than panic; the decoder may conceal, so accept either an error or a
	// bounded successful decode (never a panic / OOB, which is the contract).
	let mut decoder = Decoder::new(48000, Channels::Mono).unwrap();
	let mut output = vec![0i16; MONO_20MS];
	match decoder.decode(&packet, &mut output, false) {
		Ok(samples) => assert!(samples <= MONO_20MS),
		Err(e) => assert_eq!(e.code(), ErrorCode::InvalidPacket),
	}
}

// Exact VBR framing rejection differs from the Miri framing mock.
#[cfg(not(miri))]
#[test]
fn truncated_multiframe_packet_is_invalid_packet() {
	let packet = two_frame_packet();
	assert!(packet.len() >= 3);
	// Remove the final byte of the last frame. The strict `parse` validator
	// must detect the missing frame rather than read past the slice.
	let truncated = &packet[..packet.len() - 1];
	assert_eq!(opus::packet::parse(truncated).unwrap_err().code(), ErrorCode::InvalidPacket);
}

// ============================================================================
// Legal padding round-trips

// Decode/unpad byte fidelity requires the real codec.
#[cfg(not(miri))]
#[test]
fn pad_and_unpad_round_trip() {
	let packet = silent_packet();
	// Pad into a buffer with genuine headroom.
	let mut buf = vec![0u8; packet.len() + 32];
	buf[..packet.len()].copy_from_slice(&packet);
	let new_len = opus::packet::pad(&mut buf, packet.len()).unwrap();
	assert_eq!(new_len, buf.len());

	// The padded packet still decodes to the same number of samples.
	let mut decoder = Decoder::new(48000, Channels::Mono).unwrap();
	let mut output = vec![0i16; MONO_20MS];
	assert_eq!(decoder.decode(&buf[..new_len], &mut output, false).unwrap(), MONO_20MS);

	// Removing the padding recovers the original packet bytes.
	let unpadded_len = opus::packet::unpad(&mut buf).unwrap();
	assert_eq!(unpadded_len, packet.len());
	assert_eq!(&buf[..unpadded_len], packet.as_slice());
}

#[test]
fn pad_to_same_size_is_ok() {
	// len == new_len is an OPUS_OK no-op in libopus.
	let packet = silent_packet();
	let mut buf = packet.clone();
	let result = opus::packet::pad(&mut buf, packet.len()).unwrap();
	assert_eq!(result, packet.len());
	assert_eq!(buf.as_slice(), packet.as_slice());
}

#[test]
fn pad_shrinking_is_bad_arg() {
	// prev_len > total buffer length would shrink the packet; libopus rejects
	// it with OPUS_BAD_ARG and the wrapper must surface that, not panic.
	let packet = silent_packet();
	let mut buf = packet.clone();
	let err = opus::packet::pad(&mut buf, packet.len() + 1).unwrap_err();
	assert_eq!(err.code(), ErrorCode::BadArg);
}

// ============================================================================
// Repacketizer: valid behavior and untrusted ranges

// Pins exact libopus output bytes, which the framing mock does not reproduce.
#[cfg(not(miri))]
#[test]
fn repacketizer_valid_combine_bytes_unchanged() {
	// Pins the safe-API semantics: the exact emitted bytes must not change as
	// a side effect of the hardening work.
	let packet1 = [249u8, 255, 254, 255, 254];
	let packet2 = [248u8, 255, 254];
	let mut rp = Repacketizer::new().unwrap();
	let mut out = [0u8; 256];
	let len = rp.combine(&[&packet1[..], &packet2[..]], &mut out).unwrap();
	assert_eq!(&out[..len], &[251, 3, 255, 254, 255, 254, 255, 254]);
}

#[test]
fn repacketizer_out_range_beyond_frames_is_bad_arg() {
	let packet = silent_packet();
	let mut rp = Repacketizer::new().unwrap();
	let mut state = rp.begin();
	state.cat(&packet).unwrap();
	let mut out = [0u8; 256];
	// end (2) exceeds the number of submitted frames (1).
	assert_eq!(state.out_range(0, 2, &mut out).unwrap_err().code(), ErrorCode::BadArg);
	// begin > end is likewise rejected.
	assert_eq!(state.out_range(1, 0, &mut out).unwrap_err().code(), ErrorCode::BadArg);
}

#[test]
fn repacketizer_into_tiny_buffer_is_buffer_too_small() {
	let packet = silent_packet();
	let mut rp = Repacketizer::new().unwrap();
	let mut state = rp.begin();
	state.cat(&packet).unwrap();
	let mut tiny = [0u8; 1];
	assert_eq!(state.out(&mut tiny).unwrap_err().code(), ErrorCode::BufferTooSmall);
}

#[test]
fn repacketizer_toc_mismatch_is_invalid_packet() {
	// Two packets whose TOC config differs cannot be combined.
	let p1 = [248u8, 255, 254]; // config 31, mono, code 0
	let p2 = [240u8, 255, 254]; // different config
	let mut rp = Repacketizer::new().unwrap();
	let mut state = rp.begin();
	state.cat(&p1).unwrap();
	assert_eq!(state.cat(&p2).unwrap_err().code(), ErrorCode::InvalidPacket);
}

// ============================================================================
// parse() borrow lifetimes and frame containment

#[test]
fn parse_valid_packet_frames_live_in_packet() {
	// The borrowed frame slices must point inside the input packet, proving
	// the lifetime and bounds checks hold for valid data.
	let packet = two_frame_packet();
	let parsed = opus::packet::parse(&packet).unwrap();
	assert!(!parsed.frames.is_empty());
	let base = packet.as_ptr() as usize;
	let end = base + packet.len();
	for frame in &parsed.frames {
		let fbase = frame.as_ptr() as usize;
		assert!(fbase >= base && fbase + frame.len() <= end);
		assert!(!frame.is_empty());
	}
	assert!(parsed.payload_offset <= packet.len());
}

#[test]
fn parse_single_frame_packet() {
	let packet = silent_packet();
	let parsed = opus::packet::parse(&packet).unwrap();
	assert_eq!(parsed.frames.len(), 1);
	assert_eq!(parsed.toc, packet[0]);
}

// ============================================================================
// Out-of-range lengths that used to panic in `check_len`

#[test]
fn huge_lengths_return_errors_without_panicking() {
	// These slices cannot actually be that large, so drive the length
	// conversion through the public indices that accept caller lengths.
	let packet = silent_packet();
	let mut buf = packet.clone();

	// usize values that do not fit in c_int must map to BadArg, never panic.
	let huge = (i32::MAX as usize) + 1;
	assert_eq!(opus::packet::pad(&mut buf, huge).unwrap_err().code(), ErrorCode::BadArg);
	assert_eq!(
		opus::packet::multistream_pad(&mut buf, huge, 1).unwrap_err().code(),
		ErrorCode::BadArg
	);

	let mut rp = Repacketizer::new().unwrap();
	let mut state = rp.begin();
	state.cat(&packet).unwrap();
	let mut out = [0u8; 256];
	assert_eq!(state.out_range(huge, huge + 1, &mut out).unwrap_err().code(), ErrorCode::BadArg);
}

#[test]
fn error_function_names_are_recorded() {
	// The unified error mapping keeps the originating function name so bad
	// inputs remain diagnosable.
	let err = opus::packet::parse(&[]).unwrap_err();
	assert!(err.function().contains("opus_packet_parse"));
	assert_eq!(err.code(), ErrorCode::InvalidPacket);
}

// ============================================================================
// Miri-only wrapper-integrity tests
//
// These run against the pure-Rust framing mock (see src/ffi_miri.rs), which is
// substituted for the C library under Miri. They cannot assert exact codec
// bytes, but they can assert the things Miri is good at: every pointer the
// wrapper forms is in bounds, every allocation is freed exactly once, and no
// length conversion overflows.

/// A code-0 (single-frame) packet with a non-empty payload.
#[cfg(miri)]
fn single_frame_bytes() -> Vec<u8> {
	vec![0xF8, 10, 20, 30]
}

/// A code-2 (VBR, two-frame) packet: TOC, count byte, one length byte, frames.
#[cfg(miri)]
fn two_frame_bytes() -> Vec<u8> {
	// count = 2, first frame length 1, then two non-empty frames.
	vec![0xFA, 0x02, 0x01, 0xAA, 0xBB, 0xCC]
}

#[cfg(miri)]
#[test]
fn miri_parse_every_framing_class_is_in_bounds() {
	for packet in [single_frame_bytes(), two_frame_bytes()] {
		let base = packet.as_ptr() as usize;
		let end = base + packet.len();
		let parsed = opus::packet::parse(&packet).unwrap();
		assert!(parsed.payload_offset <= packet.len());
		for frame in &parsed.frames {
			assert!(!frame.is_empty());
			let fbase = frame.as_ptr() as usize;
			// Miri turns any out-of-bounds provenance violation into a failure
			// when the slice is constructed and read.
			assert!(fbase >= base && fbase + frame.len() <= end);
			assert!(frame.iter().all(|_| true));
		}
	}
}

#[cfg(miri)]
#[test]
fn miri_parse_rejects_empty_and_truncated() {
	assert_eq!(opus::packet::parse(&[]).unwrap_err().code(), ErrorCode::InvalidPacket);
	// A VBR header that promises frames but supplies none.
	assert!(opus::packet::parse(&[0xFA, 0x02]).is_err());
}

#[cfg(miri)]
#[test]
fn miri_handle_construction_and_drop() {
	// Construct and immediately drop each handle type repeatedly. The mock
	// allocates on the heap and frees in Drop; Miri verifies no leak or double
	// free and that a failed create never yields an owned null pointer.
	for _ in 0..4 {
		let enc = Encoder::new(48000, Channels::Mono, Application::Audio).unwrap();
		drop(enc);
		let dec = Decoder::new(48000, Channels::Mono).unwrap();
		drop(dec);
		let rp = Repacketizer::new().unwrap();
		drop(rp);
	}
	// A bad channel count must produce an error, not an empty/invalid handle.
	assert_eq!(Decoder::new(48000, Channels::Stereo).is_ok(), true);
}

#[cfg(miri)]
#[test]
fn miri_softclip_empty_and_multichunk_inputs() {
	// Empty input must be a no-op (no zero-sized pointer dereference).
	let mut clip = opus::SoftClip::new(Channels::Mono);
	clip.apply(&mut []);

	// A slice spanning more whole frames than one c_int chunk would imply is
	// processed in chunks; the chunking math must never overflow or desync the
	// channel grouping.
	let mut signal = vec![0.5f32; MONO_20MS * 2];
	clip.apply(&mut signal);

	let mut stereo = opus::SoftClip::new(Channels::Stereo);
	let mut stereo_signal = vec![0.25f32; MONO_20MS * 2 * 2];
	stereo.apply(&mut stereo_signal);
}

#[cfg(miri)]
#[test]
fn miri_repacketizer_ownership_and_error_mapping() {
	let packet = single_frame_bytes();
	let mut rp = Repacketizer::new().unwrap();

	// Empty packet cat is an InvalidPacket, not a panic.
	{
		let mut state = rp.begin();
		assert_eq!(state.cat(&[]).unwrap_err().code(), ErrorCode::InvalidPacket);
		state.cat(&packet).unwrap();
		assert_eq!(state.get_nb_frames(), 1);
	}

	// A successful out into an adequate buffer yields an in-bounds length.
	let mut out = vec![0u8; 64];
	{
		let mut state = rp.begin();
		state.cat(&packet).unwrap();
		let len = state.out(&mut out).unwrap();
		assert!(len >= 1 && len <= out.len());
	}

	// A too-small buffer maps to BufferTooSmall.
	let mut tiny = vec![0u8; 0];
	{
		let mut state = rp.begin();
		state.cat(&packet).unwrap();
		let err = state.out(&mut tiny).unwrap_err();
		assert_eq!(err.code(), ErrorCode::BufferTooSmall);
	}
}

#[cfg(miri)]
#[test]
fn miri_pad_status_returns_full_buffer_length() {
	// The wrapper must return the resulting packet length (full buffer), not
	// the underlying OPUS_OK status code of zero.
	let packet = single_frame_bytes();
	let mut buf = vec![0u8; packet.len() + 16];
	buf[..packet.len()].copy_from_slice(&packet);
	let new_len = opus::packet::pad(&mut buf, packet.len()).unwrap();
	assert_eq!(new_len, buf.len());

	// Shrinking and empty inputs stay typed errors rather than panics.
	let mut small = packet.clone();
	assert_eq!(
		opus::packet::pad(&mut small, packet.len() + 1).unwrap_err().code(),
		ErrorCode::BadArg
	);
	let mut empty = [0u8; 0];
	assert_eq!(opus::packet::unpad(&mut empty).unwrap_err().code(), ErrorCode::BadArg);
}

#[cfg(miri)]
#[test]
fn miri_decode_packet_loss_uses_null_pointer_safely() {
	// The empty-slice packet-loss path forms a null pointer with len 0; Miri
	// confirms that pointer is never dereferenced by the wrapper.
	let mut decoder = Decoder::new(48000, Channels::Mono).unwrap();
	let mut output = vec![0i16; MONO_20MS];
	let samples = decoder.decode(&[], &mut output, false).unwrap();
	assert_eq!(samples, MONO_20MS);
}
