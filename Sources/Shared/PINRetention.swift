import Foundation

/// How long the helper keeps a PIN the user chose to remember (see PINStore). The raw value
/// is the duration in seconds.
enum PINRetention: Int, CaseIterable {
	case never = 0
	case oneHour = 3600
	case oneDay = 86400

	/// When a PIN entered at now stops being used, or nil if it is not remembered at all.
	func expiry(from now: Date) -> Date? {
		if self == .never {
			return nil
		}
		return now.addingTimeInterval(TimeInterval(rawValue))
	}

	/// The longest option. A stored expiry further ahead than this is not trusted.
	static let longest = TimeInterval(allCases.map(\.rawValue).max() ?? 0)
}

/// The expiry stored next to a remembered PIN, and whether it still allows using the PIN.
enum PINExpiry {
	/// True while a PIN with this expiry may be used at now. An expiry further ahead than the
	/// longest option means the clock was turned back (or the item edited), so it is refused.
	static func isValid(_ expiry: Date, at now: Date) -> Bool {
		return now < expiry && expiry.timeIntervalSince(now) <= PINRetention.longest
	}

	/// Whole seconds since 1970, as ASCII digits.
	static func encode(_ expiry: Date) -> Data {
		return Data(String(Int64(expiry.timeIntervalSince1970.rounded(.down))).utf8)
	}

	static func decode(_ data: Data) -> Date? {
		guard let text = String(data: data, encoding: .utf8), let seconds = Int64(text) else {
			return nil
		}
		return Date(timeIntervalSince1970: TimeInterval(seconds))
	}
}
