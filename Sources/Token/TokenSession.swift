import CryptoTokenKit

/// DER DigestInfo prefixes for PKCS#1 v1.5 signatures. The helper only uses CKM_RSA_PKCS,
/// which every RSA module offers (SimplySign has no raw RSA and no PSS), so the token
/// accepts digests and wraps them itself.
private let digestInfoPrefixes: [(algorithm: SecKeyAlgorithm, digestLength: Int, prefix: [UInt8])] = [
	(.rsaSignatureDigestPKCS1v15SHA1, 20, [0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14]),
	(.rsaSignatureDigestPKCS1v15SHA224, 28, [0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c]),
	(.rsaSignatureDigestPKCS1v15SHA256, 32, [0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20]),
	(.rsaSignatureDigestPKCS1v15SHA384, 48, [0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30]),
	(.rsaSignatureDigestPKCS1v15SHA512, 64, [0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40]),
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

		let digestInfo: Data
		if let entry = digestInfoPrefixes.first(where: { algorithm.isAlgorithm($0.algorithm) }) {
			guard dataToSign.count == entry.digestLength else {
				throw TKError(.badParameter)
			}
			digestInfo = Data(entry.prefix) + dataToSign
		} else if algorithm.isAlgorithm(.rsaSignatureDigestPKCS1v15Raw) {
			digestInfo = dataToSign
		} else {
			throw TKError(.badParameter)
		}
		return try HelperClient.sign(digestInfo: digestInfo, keyID: keyID)
	}
}

enum HelperClient {
	static func sign(digestInfo: Data, keyID: String) throws -> Data {
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
		proxy?.signDigestInfo(digestInfo, keyID: keyID) { signature, message in
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
