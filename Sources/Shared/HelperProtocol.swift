import Foundation

/// Identifiers shared by the app, the helper and the token extension. They must match
/// Resources/*/Info.plist and Resources/Token/Token.entitlements.
enum Identifiers {
	static let app = "io.github.masterrok.MacTokenBridge"
	static let tokenClass = "io.github.masterrok.MacTokenBridge.Token"
	static let helperService = "io.github.masterrok.MacTokenBridge.Helper"
}

/// XPC interface the token extension uses to reach the helper, which owns the PKCS#11
/// session. The extension is sandboxed and cannot load a PKCS#11 module itself.
@objc protocol HelperProtocol {
	/// Signs a DER-encoded DigestInfo with CKM_RSA_PKCS using the key with the given CKA_ID (hex).
	func signDigestInfo(_ digestInfo: Data, keyID: String, reply: @escaping (Data?, String?) -> Void)
}
