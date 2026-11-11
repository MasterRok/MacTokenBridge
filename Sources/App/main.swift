import CryptoTokenKit
import Foundation
import Security

let launchAgentPath = NSHomeDirectory() + "/Library/LaunchAgents/\(Identifiers.helperService).plist"
let helperLogPath = NSHomeDirectory() + "/Library/Logs/MacTokenBridge.log"

let usage = """
	usage: MacTokenBridge <command>
	  install [--module PATH]  register the helper and the token's certificates
	                           (default module: the one already installed, else the first of
	                           \(KnownModules.paths.joined(separator: "\n                           ")))
	  uninstall                remove the token and the helper
	  status                   show what is registered
	  selftest                 sign a random digest through the system keychain, like a browser does
	Opened from Finder (or with --gui) it runs install and reports in a dialog.
	"""

func fail(_ message: String) -> Never {
	FileHandle.standardError.write(Data("error: \(message)\n".utf8))
	exit(1)
}

func driverConfiguration() -> TKTokenDriver.Configuration? {
	return TKTokenDriver.Configuration.driverConfigurations[Identifiers.tokenClass]
}

/// The module the installed LaunchAgent passes to the helper, if any.
func installedModulePath() -> String? {
	guard let plist = NSDictionary(contentsOfFile: launchAgentPath),
		let arguments = plist["ProgramArguments"] as? [String],
		let flag = arguments.firstIndex(of: "--module"), flag + 1 < arguments.count else {
		return nil
	}
	return arguments[flag + 1]
}

func printStatus() {
	print("module: \(installedModulePath() ?? "not installed")")
	print("helper log: \(helperLogPath)")
	guard let driver = driverConfiguration() else {
		print("token extension: not registered with macOS")
		return
	}
	if driver.tokenConfigurations.isEmpty {
		print("certificates: none registered")
	}
	for (instanceID, config) in driver.tokenConfigurations {
		let labels = Set(config.keychainItems.compactMap { $0.label }).sorted()
		print("token \(instanceID): \(labels.joined(separator: ", "))")
	}
}

/// Registers one token whose keychain items mirror the certificates and keys on the PKCS#11 token.
/// Each key's objectID carries the PKCS#11 CKA_ID the helper uses to find the private key.
/// Returns the certificate names.
func registerToken(serial: String, certificates: [TokenCertificate]) throws -> [String] {
	guard let driver = driverConfiguration() else {
		throw P11Error(rv: 0, operation: "token extension not registered with macOS")
	}
	var items = [TKTokenKeychainItem]()
	var names = [String]()
	for entry in certificates {
		guard let certificate = SecCertificateCreateWithData(nil, entry.der as CFData) else {
			log("skipping a certificate macOS cannot parse")
			continue
		}
		let label = (SecCertificateCopySubjectSummary(certificate) as String?) ?? "PKCS#11"
		let id = hex(entry.keyID)
		guard let certItem = TKTokenKeychainCertificate(certificate: certificate, objectID: "cert:\(id)"),
			let keyItem = TKTokenKeychainKey(certificate: certificate, objectID: "key:\(id)") else {
			log("skipping \(label): unsupported key")
			continue
		}
		certItem.label = label
		keyItem.label = label
		keyItem.canSign = true
		keyItem.canDecrypt = false
		keyItem.canPerformKeyExchange = false
		keyItem.isSuitableForLogin = false
		items += [certItem, keyItem]
		names.append(label)
	}
	guard !items.isEmpty else {
		throw P11Error(rv: UInt(P11_ERR_NOT_FOUND), operation: "find certificates")
	}

	for existing in driver.tokenConfigurations.keys {
		driver.removeTokenConfiguration(for: existing)
	}
	let config = driver.addTokenConfiguration(for: "pkcs11-\(serial.isEmpty ? "token" : serial)")
	config.keychainItems = items
	return names
}

@discardableResult
func launchctl(_ args: [String]) -> Int32 {
	let process = Process()
	process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
	process.arguments = args
	process.standardError = FileHandle.nullDevice
	try? process.run()
	process.waitUntilExit()
	return process.terminationStatus
}

func installLaunchAgent(modulePath: String) {
	let agent: [String: Any] = [
		"Label": Identifiers.helperService,
		"ProgramArguments": [Bundle.main.executablePath!, "helper", "--module", modulePath],
		"MachServices": [Identifiers.helperService: true],
		"StandardErrorPath": helperLogPath,
		"ProcessType": "Interactive",
	]
	let plist = try! PropertyListSerialization.data(fromPropertyList: agent, format: .xml, options: 0)
	try? FileManager.default.createDirectory(
		atPath: (launchAgentPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
	FileManager.default.createFile(atPath: launchAgentPath, contents: plist)

	let domain = "gui/\(getuid())"
	launchctl(["bootout", "\(domain)/\(Identifiers.helperService)"])
	guard launchctl(["bootstrap", domain, launchAgentPath]) == 0 else {
		fail("launchctl bootstrap failed")
	}
	print("helper installed: \(launchAgentPath)")
}

/// The token's certificates, or nil when the token is not available or holds no usable certificate.
func readCertificates(modulePath: String) -> (serial: String, certificates: [TokenCertificate])? {
	let session = PKCS11Session(modulePath: modulePath)
	defer {
		session.shutdown()
	}
	do {
		let found = try session.certificates()
		if found.certificates.isEmpty {
			print("the token holds no user certificates")
			return nil
		}
		return found
	} catch {
		print("token not readable now: \(error)")
		return nil
	}
}

func install(modulePath requested: String?, gui: Bool) {
	func report(_ message: String) {
		print(message)
		if gui {
			showMessage(message, wait: true)
		}
	}

	guard let modulePath = requested ?? installedModulePath() ?? KnownModules.firstInstalled() else {
		report(Strings.noModule)
		exit(1)
	}
	guard FileManager.default.fileExists(atPath: modulePath) else {
		fail("no such module: \(modulePath)")
	}
	print("module: \(modulePath)")

	// Read the certificates before the helper starts, so two processes never use the module at once.
	launchctl(["bootout", "gui/\(getuid())/\(Identifiers.helperService)"])
	let alreadyRegistered = driverConfiguration()?.tokenConfigurations.isEmpty == false
	var found = readCertificates(modulePath: modulePath)
	// Opened from Finder with nothing registered yet (e.g. the cloud signing app is not signed in):
	// let the user fix that and try again instead of having to find and reopen the app.
	while found == nil && gui && !alreadyRegistered && askRetry(Strings.noCertificateYet) {
		found = readCertificates(modulePath: modulePath)
	}

	installLaunchAgent(modulePath: modulePath)

	guard let found else {
		// Reinstalling after a rebuild should not require the token if it is already registered.
		if alreadyRegistered {
			print("keeping the registered certificates")
			return
		}
		// In GUI mode the retry dialog has already said this.
		print(Strings.noCertificateYet)
		exit(1)
	}
	do {
		let names = try registerToken(serial: found.serial, certificates: found.certificates)
		report(Strings.installed(certificates: names))
	} catch {
		report(Strings.noCertificateYet)
		fail("\(error)")
	}
}

func uninstall() {
	if let driver = driverConfiguration() {
		for existing in driver.tokenConfigurations.keys {
			driver.removeTokenConfiguration(for: existing)
			print("removed token \(existing)")
		}
	}
	launchctl(["bootout", "gui/\(getuid())/\(Identifiers.helperService)"])
	try? FileManager.default.removeItem(atPath: launchAgentPath)
	print("helper removed")
}

/// Signs through the system keychain exactly like a browser does: token identity -> extension -> helper -> module.
func selfTest() {
	let query: [String: Any] = [
		kSecClass as String: kSecClassIdentity,
		kSecAttrAccessGroup as String: kSecAttrAccessGroupToken,
		kSecMatchLimit as String: kSecMatchLimitAll,
		kSecReturnRef as String: true,
	]
	var result: CFTypeRef?
	guard SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess, let identities = result as? [SecIdentity] else {
		fail("no token identities found")
	}
	for identity in identities {
		var certificate: SecCertificate?
		var key: SecKey?
		SecIdentityCopyCertificate(identity, &certificate)
		SecIdentityCopyPrivateKey(identity, &key)
		guard let certificate, let key, let attributes = SecKeyCopyAttributes(key) as? [String: Any],
			(attributes[kSecAttrTokenID as String] as? String)?.hasPrefix(Identifiers.tokenClass) == true else {
			continue
		}
		let algorithm = SecKeyAlgorithm.rsaSignatureDigestPKCS1v15SHA256
		print("identity: \(SecCertificateCopySubjectSummary(certificate) as String? ?? "?")")
		print("supports rsaSignatureDigestPKCS1v15SHA256: \(SecKeyIsAlgorithmSupported(key, .sign, algorithm))")

		var digest = Data(count: 32)
		_ = digest.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, 32, $0.baseAddress!) }
		var error: Unmanaged<CFError>?
		guard let signature = SecKeyCreateSignature(key, algorithm, digest as CFData, &error) as Data? else {
			fail("signature failed: \(error!.takeRetainedValue())")
		}
		let publicKey = SecCertificateCopyKey(certificate)!
		let valid = SecKeyVerifySignature(publicKey, algorithm, digest as CFData, signature as CFData, &error)
		print("signature: \(signature.count) bytes, verifies with certificate: \(valid)")
		exit(valid ? 0 : 1)
	}
	fail("no MacTokenBridge identity found")
}

func option(_ name: String, in args: [String]) -> String? {
	guard let index = args.firstIndex(of: name), index + 1 < args.count else {
		return nil
	}
	return args[index + 1]
}

let args = Array(CommandLine.arguments.dropFirst())
switch args.first {
case "helper":
	guard let modulePath = option("--module", in: args) else {
		fail("helper needs --module")
	}
	runHelper(modulePath: modulePath)
case "install":
	install(modulePath: option("--module", in: args), gui: args.contains("--gui"))
case "uninstall":
	uninstall()
case "status":
	printStatus()
case "selftest":
	selfTest()
case nil where isatty(STDIN_FILENO) == 0, "--gui":
	// Opened from Finder: there is no terminal to print to.
	install(modulePath: nil, gui: true)
case nil, "help", "--help", "-h":
	print(usage)
default:
	fail("unknown command \(args[0])\n\(usage)")
}
