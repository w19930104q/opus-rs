extern crate opus;

fn main() {
	// A parsed Packet borrows the input slice; it must not be allowed to
	// outlive it.
	let parsed = {
		let packet = vec![248u8, 255, 254];
		opus::packet::parse(&packet).unwrap()
	};
	println!("{:?}", parsed.toc);
}
