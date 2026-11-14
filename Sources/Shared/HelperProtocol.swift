import Foundation

/// Identifiers shared by the app, the helper and the token extension. They must match
/// Resources/*/Info.plist and Resources/Token/Token.entitlements.
enum Identifiers {
	static let app = "io.github.masterrok.MacTokenBridge"
	static let tokenClass = "io.github.masterrok.MacTokenBridge.Token"
	static let helperService = "io.github.masterrok.MacTokenBridge.Helper"
}

/// PKCS#11 signature mechanisms the helper uses; raw values are the CKM_* constants.
enum SignMechanism: Int {
	/// CKM_RSA_PKCS over a DER DigestInfo: a PKCS#1 v1.5 signature.
	case rsaPKCS1 = 0x1
	/// CKM_ECDSA over a raw digest. The helper returns the signature as X9.62 DER.
	case ecdsa = 0x1041
}

/// XPC interface the token extension uses to reach the helper, which owns the PKCS#11
/// session. The extension is sandboxed and cannot load a PKCS#11 module itself.
@objc protocol HelperProtocol {
	/// Signs data with the key with the given CKA_ID (hex). mechanism is a SignMechanism raw value;
	/// the reply carries the signature in the format macOS expects for it.
	func sign(_ data: Data, mechanism: Int, keyID: String, reply: @escaping (Data?, String?) -> Void)
}
