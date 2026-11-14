import CryptoTokenKit

/// DER DigestInfo prefixes for PKCS#1 v1.5 signatures. For RSA keys the helper only uses CKM_RSA_PKCS,
/// which every RSA module offers (SimplySign has no raw RSA and no PSS), so the token
/// accepts digests and wraps them itself.
private let digestInfoPrefixes: [(algorithm: SecKeyAlgorithm, digestLength: Int, prefix: [UInt8])] = [
	(.rsaSignatureDigestPKCS1v15SHA1, 20, [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
	(.rsaSignatureDigestPKCS1v15SHA224, 28, [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]),
	(.rsaSignatureDigestPKCS1v15SHA256, 32, [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
	(.rsaSignatureDigestPKCS1v15SHA384, 48, [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
	(.rsaSignatureDigestPKCS1v15SHA512, 64, [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
]

/// ECDSA digest algorithms and the digest length each one requires. CKM_ECDSA signs a digest
/// of any length, so the plain .ecdsaSignatureDigestX962 is accepted as well.
private let ecdsaDigestLengths: [(algorithm: SecKeyAlgorithm, digestLength: Int)] = [
	(.ecdsaSignatureDigestX962SHA1, 20),
	(.ecdsaSignatureDigestX962SHA224, 28),
	(.ecdsaSignatureDigestX962SHA256, 32),
	(.ecdsaSignatureDigestX962SHA384, 48),
	(.ecdsaSignatureDigestX962SHA512, 64),
]

final class TokenSession: TKTokenSession, TKTokenSessionDelegate {
	override init(token: TKToken) {
		super.init(token: token)
		delegate = self
	}

	func tokenSession(_ session: TKTokenSession, supports operation: TKTokenOperation, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) -> Bool {
		guard operation == .signData else {
			return false
		}
		if isECKey(keyObjectID) {
			return algorithm.isAlgorithm(.ecdsaSignatureDigestX962)
				|| ecdsaDigestLengths.contains { algorithm.isAlgorithm($0.algorithm) }
		}
		if algorithm.isAlgorithm(.rsaSignatureDigestPKCS1v15Raw) {
			return true
		}
		return digestInfoPrefixes.contains { algorithm.isAlgorithm($0.algorithm) }
	}

	func tokenSession(_ session: TKTokenSession, sign dataToSign: Data, keyObjectID: Any, algorithm: TKTokenKeyAlgorithm) throws -> Data {
		guard let objectID = keyObjectID as? String, objectID.hasPrefix("key:") else {
			throw TKError(.objectNotFound)
		}
		let keyID = String(objectID.dropFirst("key:".count))

		if isECKey(keyObjectID) {
			return try HelperClient.sign(ecdsaDigest(dataToSign, algorithm: algorithm), mechanism: .ecdsa, keyID: keyID)
		}
		return try HelperClient.sign(digestInfo(dataToSign, algorithm: algorithm), mechanism: .rsaPKCS1, keyID: keyID)
	}

	/// Keys are registered from their certificates (see registerToken), which sets keyType.
	/// Anything that is not an EC key takes the RSA path. The lookup goes through the token's
	/// configuration: keychainContents is nil for a persistent token.
	private func isECKey(_ keyObjectID: Any) -> Bool {
		guard let key = try? token.configuration.key(for: keyObjectID) else {
			return false
		}
		return key.keyType == kSecAttrKeyTypeECSECPrimeRandom as String
	}

	/// The DER DigestInfo CKM_RSA_PKCS signs for a PKCS#1 v1.5 algorithm.
	private func digestInfo(_ dataToSign: Data, algorithm: TKTokenKeyAlgorithm) throws -> Data {
		if let entry = digestInfoPrefixes.first(where: { algorithm.isAlgorithm($0.algorithm) }) {
			guard dataToSign.count == entry.digestLength else {
				throw TKError(.badParameter)
			}
			return Data(entry.prefix) + dataToSign
		}
		if algorithm.isAlgorithm(.rsaSignatureDigestPKCS1v15Raw) {
			return dataToSign
		}
		throw TKError(.badParameter)
	}

	/// The digest CKM_ECDSA signs, checked against the algorithm's digest length.
	private func ecdsaDigest(_ dataToSign: Data, algorithm: TKTokenKeyAlgorithm) throws -> Data {
		if let entry = ecdsaDigestLengths.first(where: { algorithm.isAlgorithm($0.algorithm) }) {
			guard dataToSign.count == entry.digestLength else {
				throw TKError(.badParameter)
			}
			return dataToSign
		}
		if algorithm.isAlgorithm(.ecdsaSignatureDigestX962) && !dataToSign.isEmpty {
			return dataToSign
		}
		throw TKError(.badParameter)
	}
}

enum HelperClient {
	static func sign(_ data: Data, mechanism: SignMechanism, keyID: String) throws -> Data {
		let connection = NSXPCConnection(machServiceName: Identifiers.helperService, options: [])
		connection.remoteObjectInterface = NSXPCInterface(with: HelperProtocol.self)
		connection.resume()
		defer {
			connection.invalidate()
		}

		var result: Result<Data, Error> = .failure(TKError(.communicationError))
		let proxy = connection.synchronousRemoteObjectProxyWithErrorHandler { error in
			log.error("helper connection failed: \(error.localizedDescription, privacy: .public)")
			result = .failure(TKError(.communicationError))
		} as? HelperProtocol
		proxy?.sign(data, mechanism: mechanism.rawValue, keyID: keyID) { signature, message in
			if let signature {
				result = .success(signature)
			} else {
				log.error("helper refused to sign: \(message ?? "?", privacy: .public)")
				let cancelled = message?.contains("cancelled") == true
				result = .failure(TKError(cancelled ? .canceledByUser : .authenticationFailed))
			}
		}
		return try result.get()
	}
}
