import Foundation
import Security

/// PINs the user chose to remember, as generic passwords in the login keychain: one item per
/// token, with the expiry next to it. Items stay on this Mac (not synchronizable), are deleted
/// when found expired, and the PIN itself is never logged.
enum PINStore {
	private static let service = "\(Identifiers.app).pin"

	/// Matches this app's remembered PINs: the one for token, or all of them.
	private static func query(token: String?) -> [String: Any] {
		var query: [String: Any] = [
			kSecClass as String: kSecClassGenericPassword,
			kSecAttrService as String: service,
		]
		if let token {
			query[kSecAttrAccount as String] = token
		}
		return query
	}

	static func save(pin: String, token: String, expires: Date) {
		forget(token: token)
		var item = query(token: token)
		item.merge([
			kSecAttrLabel as String: "MacTokenBridge PIN",
			kSecAttrGeneric as String: PINExpiry.encode(expires),
			kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
			kSecAttrSynchronizable as String: false,
			kSecValueData as String: Data(pin.utf8),
		]) { _, new in
			new
		}
		let status = SecItemAdd(item as CFDictionary, nil)
		if status != errSecSuccess {
			log("could not remember the PIN: OSStatus \(status)")
		}
	}

	/// The remembered PIN for token while it is valid. An expired or unreadable item is deleted.
	static func load(token: String) -> String? {
		var lookup = query(token: token)
		lookup[kSecReturnAttributes as String] = true
		lookup[kSecReturnData as String] = true
		var result: CFTypeRef?
		let status = SecItemCopyMatching(lookup as CFDictionary, &result)
		if status == errSecItemNotFound {
			return nil
		}
		guard status == errSecSuccess, let item = result as? [String: Any],
			let expiryData = item[kSecAttrGeneric as String] as? Data, let expiry = PINExpiry.decode(expiryData),
			PINExpiry.isValid(expiry, at: Date()),
			let pinData = item[kSecValueData as String] as? Data, let pin = String(data: pinData, encoding: .utf8),
			!pin.isEmpty else {
			log(status == errSecSuccess ? "the remembered PIN expired" : "cannot read the remembered PIN: OSStatus \(status)")
			forget(token: token)
			return nil
		}
		return pin
	}

	static func forget(token: String) {
		let status = SecItemDelete(query(token: token) as CFDictionary)
		if status != errSecSuccess && status != errSecItemNotFound {
			log("could not delete the remembered PIN: OSStatus \(status)")
		}
	}

	/// Deletes every remembered PIN and returns how many there were.
	@discardableResult
	static func forgetAll() -> Int {
		var listQuery = query(token: nil)
		listQuery[kSecMatchLimit as String] = kSecMatchLimitAll
		listQuery[kSecReturnAttributes as String] = true
		var result: CFTypeRef?
		let count = SecItemCopyMatching(listQuery as CFDictionary, &result) == errSecSuccess ? (result as? [Any])?.count ?? 0 : 0
		// The file-based keychain may delete one match per call, so repeat until none is left.
		for _ in 0..<max(count, 1) {
			if SecItemDelete(query(token: nil) as CFDictionary) != errSecSuccess {
				break
			}
		}
		return count
	}
}
