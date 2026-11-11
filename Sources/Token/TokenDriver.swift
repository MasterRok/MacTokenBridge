import CryptoTokenKit
import os

let log = Logger(subsystem: Identifiers.app, category: "token")

@objc(TokenDriver)
final class TokenDriver: TKTokenDriver, TKTokenDriverDelegate {
	override init() {
		super.init()
		delegate = self
	}

	func tokenDriver(_ driver: TKTokenDriver, tokenFor configuration: TKToken.Configuration) throws -> TKToken {
		log.info("tokenFor instance \(configuration.instanceID, privacy: .public)")
		return Token(tokenDriver: self, configuration: configuration)
	}
}

final class Token: TKToken, TKTokenDelegate {
	init(tokenDriver: TokenDriver, configuration: TKToken.Configuration) {
		super.init(tokenDriver: tokenDriver, instanceID: configuration.instanceID)
		delegate = self
		keychainContents?.fill(with: configuration.keychainItems)
	}

	func createSession(_ token: TKToken) throws -> TKTokenSession {
		return TokenSession(token: token)
	}
}
