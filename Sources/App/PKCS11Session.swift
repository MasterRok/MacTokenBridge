import Foundation

struct P11Error: Error, CustomStringConvertible {
	let rv: UInt
	let operation: String

	var description: String {
		return "\(operation) failed: CK_RV 0x\(String(rv, radix: 16))"
	}
}

/// The token extension maps any helper error containing "cancelled" to TKError.canceledByUser.
struct CancelledError: Error, CustomStringConvertible {
	let what: String

	var description: String {
		return "\(what) cancelled"
	}
}

func check(_ rv: UInt, _ operation: String) throws {
	if rv != P11_OK {
		throw P11Error(rv: rv, operation: operation)
	}
}

func hex(_ data: Data) -> String {
	return data.map { String(format: "%02x", $0) }.joined()
}

func data(fromHex string: String) -> Data? {
	guard string.count % 2 == 0 else {
		return nil
	}
	var bytes = [UInt8]()
	var index = string.startIndex
	while index < string.endIndex {
		let next = string.index(index, offsetBy: 2)
		guard let byte = UInt8(string[index..<next], radix: 16) else {
			return nil
		}
		bytes.append(byte)
		index = next
	}
	return Data(bytes)
}

/// PKCS#11 modules looked for when the user does not pass --module, in order.
enum KnownModules {
	static let paths = [
		"/usr/local/lib/libSimplySignPKCS.dylib",  // Certum SimplySign (cloud)
		"/Applications/proCertumSmartSign.app/Contents/MacOS/libcryptoCertum3PKCS.dylib",  // Certum cryptoCertum cards
		"/Library/OpenSC/lib/opensc-pkcs11.so",  // OpenSC
	]

	static func firstInstalled() -> String? {
		return paths.first { FileManager.default.fileExists(atPath: $0) }
	}
}

struct TokenCertificate {
	let der: Data
	let keyID: Data
}

/// Owns the PKCS#11 session with one module. All access goes through one long-lived thread.
///
/// Behaves like Firefox: the PIN is asked once and the token stays logged in for the life of
/// the helper (until logout/reboot) or until the module drops its connection (cloud signatures
/// such as SimplySign do when their desktop app disconnects).
final class PKCS11Session {
	/// Don't repeat the "token unavailable" notice for every TLS connection of one page load.
	static let unavailableNoticeInterval: TimeInterval = 60

	/// The token is gone (card removed, cloud app not signed in); a PIN cannot help.
	private static let tokenUnavailableErrors: Set<UInt> = [
		0x30,  // CKR_DEVICE_ERROR
		0x32,  // CKR_DEVICE_REMOVED
		0xe0,  // CKR_TOKEN_NOT_PRESENT
		0xe1,  // CKR_TOKEN_NOT_RECOGNIZED
		UInt(P11_ERR_NO_TOKEN),
	]

	/// The session went stale or the module had a transient failure; a new session
	/// (keeping the module's login) usually fixes it.
	private static let staleSessionErrors: Set<UInt> = [
		0x05,  // CKR_GENERAL_ERROR
		0x06,  // CKR_FUNCTION_FAILED, seen occasionally from SimplySign between successful signatures
		0x90,  // CKR_OPERATION_ACTIVE, left over from a failed signature
		0xb0,  // CKR_SESSION_CLOSED
		0xb3,  // CKR_SESSION_HANDLE_INVALID
		UInt(P11_RV_USER_NOT_LOGGED_IN),
		UInt(P11_ERR_NOT_FOUND),  // private keys are hidden when the login was lost
	]

	let modulePath: String
	private let p11Thread = P11Thread(name: "\(Identifiers.app).p11")
	private var sessionOpen = false
	private var loggedIn = false
	private var tokenLabel = "PKCS#11"
	private var lastUnavailableNotice: Date?

	init(modulePath: String) {
		self.modulePath = modulePath
	}

	/// Token serial number and the certificates that have a key on the token
	/// (CA certificates and certificates without CKA_ID are skipped).
	func certificates() throws -> (serial: String, certificates: [TokenCertificate]) {
		return try p11Thread.sync { [self] in
			try ensureSession()
			var label = [CChar](repeating: 0, count: 64)
			var serial = [CChar](repeating: 0, count: 32)
			try check(p11_token_info(&label, label.count, &serial, serial.count), "token info")

			var result = [TokenCertificate]()
			for index in 0..<64 {
				var der = [UInt8](repeating: 0, count: 16 * 1024)
				var derLen = der.count
				var keyID = [UInt8](repeating: 0, count: 256)
				var keyIDLen = keyID.count
				var category: UInt = 0
				let rv = p11_certificate_at(index, &der, &derLen, &keyID, &keyIDLen, &category)
				if rv == P11_ERR_NOT_FOUND {
					break
				}
				try check(rv, "read certificate")
				if category == P11_CERTIFICATE_CATEGORY_AUTHORITY || keyIDLen == 0 {
					continue
				}
				result.append(TokenCertificate(der: Data(der[0..<derLen]), keyID: Data(keyID[0..<keyIDLen])))
			}
			return (String(cString: serial), result)
		}
	}

	/// Up to three attempts: as is, then with a new session (keeps the login, so no second PIN),
	/// then, if the token still looks unavailable, with a re-initialized module (a cloud app may
	/// have reconnected), otherwise with another new session.
	func sign(digestInfo: Data, keyID: Data) throws -> Data {
		return try p11Thread.sync { [self] in
			let retryable = Self.tokenUnavailableErrors.union(Self.staleSessionErrors)
			for attempt in 1...3 {
				do {
					return try signOnce(digestInfo: digestInfo, keyID: keyID)
				} catch let error as P11Error where attempt < 3 && retryable.contains(error.rv) {
					log("attempt \(attempt) failed: \(error)")
					// Re-initializing the module logs out, so only do it when the token looks unavailable.
					if attempt == 1 || !Self.tokenUnavailableErrors.contains(error.rv) {
						resetSession()
					} else {
						resetModule()
					}
				} catch let error as P11Error where Self.tokenUnavailableErrors.contains(error.rv) {
					noticeUnavailable()
					throw error
				}
			}
			preconditionFailure("the last attempt either returns or throws")
		}
	}

	/// Disconnects from the module cleanly; called when launchd stops the helper.
	func shutdown() {
		try? p11Thread.sync { [self] in
			resetModule()
		}
	}

	private func ensureSession() throws {
		if sessionOpen {
			return
		}
		try check(p11_load(modulePath), "load \(modulePath)")
		try check(p11_open_session(), "open session")
		sessionOpen = true
		loggedIn = false

		var label = [CChar](repeating: 0, count: 64)
		var serial = [CChar](repeating: 0, count: 32)
		if p11_token_info(&label, label.count, &serial, serial.count) == P11_OK {
			tokenLabel = String(cString: label)
		}
	}

	/// The old session stays open until ensureSession has opened its replacement (see p11_open_session).
	private func resetSession() {
		sessionOpen = false
		loggedIn = false
	}

	private func resetModule() {
		p11_finalize()
		sessionOpen = false
		loggedIn = false
	}

	private func ensureLogin() throws {
		if loggedIn {
			return
		}
		// Also proves the session is alive before bothering the user with a PIN, and picks up
		// a login that survived reopening the session.
		var moduleLoggedIn: Int32 = 0
		try check(p11_session_logged_in(&moduleLoggedIn), "session info")
		if moduleLoggedIn != 0 {
			loggedIn = true
			return
		}
		var message = Strings.pinPrompt(token: tokenLabel)
		for _ in 0..<3 {
			let pin = try askPIN(message: message)
			let rv = p11_login(pin)
			if rv == P11_OK {
				loggedIn = true
				log("logged in")
				return
			}
			if rv == P11_RV_PIN_LOCKED {
				throw P11Error(rv: rv, operation: "login (PIN locked)")
			}
			if rv != P11_RV_PIN_INCORRECT {
				throw P11Error(rv: rv, operation: "login")
			}
			message = Strings.wrongPIN
		}
		throw P11Error(rv: UInt(P11_RV_PIN_INCORRECT), operation: "login")
	}

	private func signOnce(digestInfo: Data, keyID: Data) throws -> Data {
		try ensureSession()
		try ensureLogin()

		var always: Int32 = 0
		try keyID.withUnsafeBytes { id in
			try check(p11_key_always_authenticate(id.bindMemory(to: UInt8.self).baseAddress, id.count, &always), "find key")
		}
		var contextPIN: String? = nil
		if always != 0 {
			contextPIN = try askPIN(message: Strings.contextPIN)
		}

		var signature = [UInt8](repeating: 0, count: 1024)
		var signatureLen = signature.count
		let rv = keyID.withUnsafeBytes { id in
			digestInfo.withUnsafeBytes { input in
				p11_sign_rsa_pkcs(
					id.bindMemory(to: UInt8.self).baseAddress, id.count,
					input.bindMemory(to: UInt8.self).baseAddress, input.count,
					contextPIN,
					&signature, &signatureLen)
			}
		}
		if rv != P11_OK {
			// A failed signature may leave the operation active (CKR_OPERATION_ACTIVE next time);
			// sign() then retries on a new session.
			throw P11Error(rv: rv, operation: "sign")
		}
		return Data(signature[0..<signatureLen])
	}

	private func noticeUnavailable() {
		if let last = lastUnavailableNotice, Date().timeIntervalSince(last) < Self.unavailableNoticeInterval {
			return
		}
		lastUnavailableNotice = Date()
		log("token unavailable")
		showMessage(Strings.tokenUnavailable, wait: false)
	}
}
