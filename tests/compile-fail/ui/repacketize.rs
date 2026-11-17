extern crate opus;

fn main() {
	let mut rp = opus::Repacketizer::new().unwrap();
	let mut wip = {
		// A short-lived packet that goes out of scope before the
		// repacketizer state holding its borrow is used.
		let packet = vec![248u8, 255, 254];
		rp.begin().cat_move(&packet).unwrap()
	};
	let mut out = [0u8; 64];
	wip.out(&mut out).unwrap();
}
