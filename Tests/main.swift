// Test runner for the pure code in Sources/Shared, built and run by scripts/test.sh.
import CryptoKit
import Foundation

var failures = 0
var checks = 0

func expect(_ condition: Bool, _ name: String, file: StaticString = #file, line: UInt = #line) {
	checks += 1
	if !condition {
		failures += 1
		print("FAIL \(name) (\(file):\(line))")
	}
}

func bytes(_ parts: [UInt8]...) -> Data {
	return Data(parts.joined())
}

func repeated(_ byte: UInt8, _ count: Int) -> [UInt8] {
	return [UInt8](repeating: byte, count: count)
}

func der(_ raw: Data) -> [UInt8]? {
	return ECDSASignature.derEncoded(raw: raw).map { [UInt8]($0) }
}

// P-256, no special cases: two 32-byte INTEGERs, short-form lengths.
expect(
	der(bytes(repeated(0x11, 32), repeated(0x22, 32)))
		== [0x30, 0x44, 0x02, 0x20] + repeated(0x11, 32) + [0x02, 0x20] + repeated(0x22, 32),
	"P-256 plain")

// High bit set: a 0x00 is prepended so the INTEGER stays positive.
expect(
	der(bytes([0x80], repeated(0x00, 31), repeated(0xff, 32)))
		== [0x30, 0x46, 0x02, 0x21, 0x00, 0x80] + repeated(0x00, 31) + [0x02, 0x21, 0x00] + repeated(0xff, 32),
	"P-256 high bit padding")

// Leading zeros are stripped; a high bit uncovered by stripping still gets its 0x00.
expect(
	der(bytes([0x00, 0x00, 0x7f], repeated(0x01, 29), [0x00, 0x80], repeated(0x02, 30)))
		== [0x30, 0x42, 0x02, 0x1e, 0x7f] + repeated(0x01, 29) + [0x02, 0x20, 0x00, 0x80] + repeated(0x02, 30),
	"P-256 leading zeros")

// A zero half encodes as the one-byte INTEGER 0.
expect(
	der(bytes(repeated(0x00, 32), [0x00, 0x01], repeated(0x00, 30)))
		== [0x30, 0x24, 0x02, 0x01, 0x00, 0x02, 0x1f, 0x01] + repeated(0x00, 30),
	"zero half")

// P-384 sizes, with and without padding.
expect(
	der(bytes(repeated(0x33, 48), repeated(0x44, 48)))
		== [0x30, 0x64, 0x02, 0x30] + repeated(0x33, 48) + [0x02, 0x30] + repeated(0x44, 48),
	"P-384 plain")
expect(
	der(bytes(repeated(0xaa, 48), repeated(0xbb, 48)))
		== [0x30, 0x66, 0x02, 0x31, 0x00] + repeated(0xaa, 48) + [0x02, 0x31, 0x00] + repeated(0xbb, 48),
	"P-384 high bit padding")

// P-521: 66-byte halves make the SEQUENCE longer than 127 bytes, so its length is long-form.
expect(
	der(bytes([0x01], repeated(0xff, 65), [0x01], repeated(0xee, 65)))
		== [0x30, 0x81, 0x88, 0x02, 0x42, 0x01] + repeated(0xff, 65) + [0x02, 0x42, 0x01] + repeated(0xee, 65),
	"P-521 long-form length")
expect(
	der(bytes([0x00, 0x00], repeated(0x55, 64), [0x00], repeated(0xff, 65)))
		== [0x30, 0x81, 0x86, 0x02, 0x40] + repeated(0x55, 64) + [0x02, 0x42, 0x00] + repeated(0xff, 65),
	"P-521 leading zeros and padding")

// Inputs that cannot be r||s.
expect(der(Data()) == nil, "empty input")
expect(der(bytes(repeated(0x11, 63))) == nil, "odd length")
expect(der(bytes([0x01])) == nil, "single byte")

// The conversion works on a slice whose indices do not start at 0.
let padded = bytes([0xde, 0xad], repeated(0x11, 32), repeated(0x22, 32))
expect(
	ECDSASignature.derEncoded(raw: padded.dropFirst(2)).map { [UInt8]($0) }
		== [0x30, 0x44, 0x02, 0x20] + repeated(0x11, 32) + [0x02, 0x20] + repeated(0x22, 32),
	"Data slice")

// Against CryptoKit as an independent encoder: random signatures hit the padding and
// leading-zero cases on their own.
let message = Data("MacTokenBridge".utf8)
for _ in 0..<300 {
	let p256 = try! P256.Signing.PrivateKey().signature(for: message)
	expect(ECDSASignature.derEncoded(raw: p256.rawRepresentation) == p256.derRepresentation, "CryptoKit P-256")
	let p384 = try! P384.Signing.PrivateKey().signature(for: message)
	expect(ECDSASignature.derEncoded(raw: p384.rawRepresentation) == p384.derRepresentation, "CryptoKit P-384")
	let p521 = try! P521.Signing.PrivateKey().signature(for: message)
	expect(ECDSASignature.derEncoded(raw: p521.rawRepresentation) == p521.derRepresentation, "CryptoKit P-521")
}

print("\(checks - failures)/\(checks) checks passed")
exit(failures == 0 ? 0 : 1)
