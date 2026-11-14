import Foundation

func testPINRetention() {
	let now = Date(timeIntervalSince1970: 1_800_000_000)

	// What the dialog offers, in order; "don't remember" first because it is the default.
	expect(PINRetention.allCases == [.never, .oneHour, .oneDay], "options and order")

	expect(PINRetention.never.expiry(from: now) == nil, "never: no expiry")
	expect(PINRetention.oneHour.expiry(from: now) == now.addingTimeInterval(3600), "one hour")
	expect(PINRetention.oneDay.expiry(from: now) == now.addingTimeInterval(86400), "one day")

	// Valid strictly before the expiry.
	let hour = now.addingTimeInterval(3600)
	expect(PINExpiry.isValid(hour, at: now), "fresh")
	expect(PINExpiry.isValid(hour, at: hour.addingTimeInterval(-1)), "one second left")
	expect(!PINExpiry.isValid(hour, at: hour), "at the expiry")
	expect(!PINExpiry.isValid(hour, at: hour.addingTimeInterval(1)), "after the expiry")

	// An expiry further ahead than the longest option means the clock went back (or the item
	// was edited): not trusted.
	let day = now.addingTimeInterval(86400)
	expect(PINExpiry.isValid(day, at: now), "a full day ahead")
	expect(!PINExpiry.isValid(day.addingTimeInterval(1), at: now), "more than a day ahead")
	expect(!PINExpiry.isValid(day, at: now.addingTimeInterval(-7200)), "clock turned back")

	// Stored next to the PIN as whole seconds since 1970.
	expect(PINExpiry.encode(hour) == Data("1800003600".utf8), "encode")
	expect(PINExpiry.decode(Data("1800003600".utf8)) == hour, "decode")
	expect(PINExpiry.decode(PINExpiry.encode(day)) == day, "round trip")
	expect(PINExpiry.encode(Date(timeIntervalSince1970: 1_800_000_000.7)) == Data("1800000000".utf8), "encode drops the fraction")
	expect(PINExpiry.decode(Data()) == nil, "decode empty")
	expect(PINExpiry.decode(Data("soon".utf8)) == nil, "decode text")
	expect(PINExpiry.decode(Data("18000 03600".utf8)) == nil, "decode with a space")
	expect(PINExpiry.decode(Data([0xff, 0xfe])) == nil, "decode invalid UTF-8")
}
