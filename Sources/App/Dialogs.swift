import Foundation

/// User-facing strings in English, Russian and Polish, picked from the system language.
enum Strings {
	private static let language: String = {
		let preferred = Locale.preferredLanguages.first ?? "en"
		for code in ["ru", "pl"] where preferred.hasPrefix(code) {
			return code
		}
		return "en"
	}()

	private static func pick(en: String, ru: String, pl: String) -> String {
		switch language {
		case "ru":
			return ru
		case "pl":
			return pl
		default:
			return en
		}
	}

	static var ok: String {
		return "OK"
	}

	static var cancel: String {
		return pick(en: "Cancel", ru: "Отмена", pl: "Anuluj")
	}

	static var tryAgain: String {
		return pick(en: "Try Again", ru: "Повторить", pl: "Spróbuj ponownie")
	}

	static func pinPrompt(token: String) -> String {
		return pick(
			en: "Enter the PIN for “\(token)” to sign in with your certificate.",
			ru: "Введите PIN для «\(token)», чтобы войти на сайт по сертификату.",
			pl: "Wprowadź PIN dla „\(token)”, aby zalogować się certyfikatem.")
	}

	static var wrongPIN: String {
		return pick(en: "Wrong PIN. Try again.", ru: "Неверный PIN. Попробуйте ещё раз.", pl: "Nieprawidłowy PIN. Spróbuj ponownie.")
	}

	static var contextPIN: String {
		return pick(en: "Confirm the signature with your PIN.", ru: "Подтвердите подпись PIN-кодом.", pl: "Potwierdź podpis kodem PIN.")
	}

	static var tokenUnavailable: String {
		return pick(
			en: "The signing token is not available. If you use a cloud signature such as SimplySign, open its desktop app, sign in, and reload the page.",
			ru: "Токен для подписи недоступен. Если у вас облачная подпись (например, SimplySign), откройте её приложение, войдите и обновите страницу.",
			pl: "Token do podpisu jest niedostępny. Jeśli używasz podpisu w chmurze (np. SimplySign), otwórz jego aplikację, zaloguj się i odśwież stronę.")
	}

	static func installed(certificates: [String]) -> String {
		let list = certificates.joined(separator: ", ")
		return pick(
			en: "MacTokenBridge is ready. Certificates: \(list). Chrome, Safari and other apps can use them now.",
			ru: "MacTokenBridge готов. Сертификаты: \(list). Теперь их видят Chrome, Safari и другие программы.",
			pl: "MacTokenBridge jest gotowy. Certyfikaty: \(list). Chrome, Safari i inne aplikacje mogą już z nich korzystać.")
	}

	static var noCertificateYet: String {
		return pick(
			en: "No certificate found yet. Connect your token (for SimplySign: open SimplySign Desktop and sign in), then open MacTokenBridge again.",
			ru: "Сертификат пока не найден. Подключите токен (для SimplySign — откройте SimplySign Desktop и войдите), затем снова откройте MacTokenBridge.",
			pl: "Nie znaleziono jeszcze certyfikatu. Podłącz token (dla SimplySign: otwórz SimplySign Desktop i zaloguj się), a następnie ponownie otwórz MacTokenBridge.")
	}

	static var noModule: String {
		return pick(
			en: "No PKCS#11 module found. Install your signature provider's software first.",
			ru: "Модуль PKCS#11 не найден. Сначала установите программу вашего провайдера подписи.",
			pl: "Nie znaleziono modułu PKCS#11. Najpierw zainstaluj oprogramowanie dostawcy podpisu.")
	}
}

/// AppleScript string literal for arbitrary text (token labels can contain quotes).
private func appleScriptString(_ text: String) -> String {
	let escaped = text
		.replacingOccurrences(of: "\\", with: "\\\\")
		.replacingOccurrences(of: "\"", with: "\\\"")
	return "\"\(escaped)\""
}

/// Runs an AppleScript dialog and returns its stdout, or nil if the user cancelled.
private func runDialog(_ script: String) throws -> String? {
	let process = Process()
	process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
	process.arguments = ["-e", script]
	let output = Pipe()
	process.standardOutput = output
	process.standardError = FileHandle.nullDevice
	try process.run()
	let raw = output.fileHandleForReading.readDataToEndOfFile()
	process.waitUntilExit()
	guard process.terminationStatus == 0 else {
		return nil
	}
	return String(decoding: raw, as: UTF8.self).trimmingCharacters(in: .newlines)
}

/// Shows a password dialog. The PIN never leaves this process except into C_Login.
/// Gives up after two minutes so an unattended dialog does not block signing forever.
func askPIN(message: String) throws -> String {
	let script = """
		display dialog \(appleScriptString(message)) with title "MacTokenBridge" default answer "" with hidden answer ¬
			buttons {\(appleScriptString(Strings.cancel)), "OK"} default button "OK" ¬
			cancel button \(appleScriptString(Strings.cancel)) with icon caution giving up after 120
		text returned of result
		"""
	guard let pin = try runDialog(script), !pin.isEmpty else {
		throw CancelledError(what: "PIN entry")
	}
	return pin
}

/// Shows message with "Try again" and "Cancel"; true when the user chose to try again.
func askRetry(_ message: String) -> Bool {
	let script = """
		display dialog \(appleScriptString(message)) with title "MacTokenBridge" ¬
			buttons {\(appleScriptString(Strings.cancel)), \(appleScriptString(Strings.tryAgain))} ¬
			default button \(appleScriptString(Strings.tryAgain)) cancel button \(appleScriptString(Strings.cancel))
		button returned of result
		"""
	return (try? runDialog(script)) == Strings.tryAgain
}

/// Shows an informational dialog. With wait == false the caller continues at once,
/// so a failing signature request returns without waiting for the user.
func showMessage(_ message: String, wait: Bool) {
	let process = Process()
	process.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
	process.arguments = [
		"-e",
		"display dialog \(appleScriptString(message)) with title \"MacTokenBridge\" buttons {\"OK\"} default button \"OK\" giving up after 120",
	]
	process.standardOutput = FileHandle.nullDevice
	process.standardError = FileHandle.nullDevice
	try? process.run()
	if wait {
		process.waitUntilExit()
	}
}

func log(_ message: String) {
	FileHandle.standardError.write(Data("\(Date()) \(message)\n".utf8))
}
