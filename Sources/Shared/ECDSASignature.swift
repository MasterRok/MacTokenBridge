import Foundation

/// PKCS#11 CKM_ECDSA returns the signature as r||s, two big-endian integers of the curve's size.
/// macOS (SecKey, and so every browser) expects X9.62: DER SEQUENCE { INTEGER r, INTEGER s }.
enum ECDSASignature {
	/// X9.62 DER encoding of a raw r||s signature, or nil if raw cannot be one (empty or odd length).
	static func derEncoded(raw: Data) -> Data? {
		let bytes = [UInt8](raw)
		guard !bytes.isEmpty, bytes.count % 2 == 0 else {
			return nil
		}
		let half = bytes.count / 2
		let body = integer(bytes[..<half]) + integer(bytes[half...])
		return Data([0x30] + length(body.count) + body)
	}

	/// DER INTEGER of a big-endian unsigned value: minimal length, positive.
	private static func integer(_ value: ArraySlice<UInt8>) -> [UInt8] {
		var content = [UInt8](value.drop { $0 == 0 })
		if content.isEmpty || content[0] & 0x80 != 0 {
			content.insert(0x00, at: 0)
		}
		return [0x02] + length(content.count) + content
	}

	/// DER length: one byte below 128, else 0x80 | number of length bytes, then the bytes.
	private static func length(_ count: Int) -> [UInt8] {
		if count < 0x80 {
			return [UInt8(count)]
		}
		var bytes = [UInt8]()
		var remaining = count
		while remaining > 0 {
			bytes.insert(UInt8(remaining & 0xff), at: 0)
			remaining >>= 8
		}
		return [0x80 | UInt8(bytes.count)] + bytes
	}
}
