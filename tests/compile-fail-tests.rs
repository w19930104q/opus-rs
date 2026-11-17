//! Compile-time (borrow/lifetime) safety checks, driven by `trybuild`.
//!
//! Each `.rs` file under `compile-fail/ui/` is expected to fail compilation
//! with the compiler diagnostics recorded alongside it in a `.stderr` file.
//! These pin down that the `'buf` lifetime on `RepacketizerState` and the
//! borrow on a parsed `Packet` cannot be escaped by safe code.
//!
//! Skipped under Miri: `trybuild` invokes the compiler and performs process /
//! filesystem operations that Miri's sandbox does not model. The lifetime
//! guarantees it checks are enforced by the borrow checker regardless.

#[cfg(not(miri))]
extern crate trybuild;

#[cfg(not(miri))]
#[test]
fn compile_fail() {
	trybuild::TestCases::new().compile_fail("tests/compile-fail/ui/*.rs");
}

#[cfg(miri)]
#[test]
fn compile_fail_skipped_under_miri() {
	// Placeholder so the target still reports a passing test under Miri.
}
