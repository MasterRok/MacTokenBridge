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

	static func retention(_ retention: PINRetention) -> String {
		switch retention {
		case .never:
			return pick(en: "Don’t remember the PIN", ru: "Не запоминать PIN", pl: "Nie zapamiętuj PIN-u")
		case .oneHour:
			return pick(en: "Remember the PIN for 1 hour", ru: "Запомнить PIN на 1 час", pl: "Zapamiętaj PIN na 1 godzinę")
		case .oneDay:
			return pick(en: "Remember the PIN for 1 day", ru: "Запомнить PIN на 1 день", pl: "Zapamiętaj PIN na 1 dzień")
		}
	}

	static var rememberedPINRefused: String {
		return pick(
			en: "The remembered PIN was not accepted and has been deleted. Enter the PIN.",
			ru: "Запомненный PIN не подошёл и удалён. Введите PIN.",
			pl: "Zapamiętany PIN nie został przyjęty i został usunięty. Wprowadź PIN.")
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

	static var moveToApplications: String {
		return pick(
			en: "Move MacTokenBridge to the Applications folder first, then open it from there.",
			ru: "Сначала перетащите MacTokenBridge в папку «Программы» и откройте его оттуда.",
			pl: "Najpierw przenieś MacTokenBridge do folderu Aplikacje i otwórz go stamtąd.")
	}

	static var registrationFailed: String {
		return pick(
			en: "macOS did not load the MacTokenBridge token extension. Restart your Mac and open MacTokenBridge again.",
			ru: "macOS не загрузила расширение MacTokenBridge. Перезагрузите Mac и снова откройте MacTokenBridge.",
			pl: "macOS nie załadował rozszerzenia MacTokenBridge. Uruchom ponownie Maca i otwórz MacTokenBridge jeszcze raz.")
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

/// Shows the PIN dialog and waits for it; offerRemember adds the choice to remember the PIN.
/// The PIN goes only into C_Login and, if the user asks for it, PINStore.
/// Gives up after two minutes so an unattended dialog does not block signing forever.
///
/// A CFUserNotification rather than an NSAlert: setting up NSApplication in the helper checks
/// the app in with LaunchServices, which tears down the running token extension (it lives in
/// the same bundle) and fails the signature it is waiting for.
func askPIN(message: String, offerRemember: Bool) throws -> (pin: String, retention: PINRetention) {
	let timeout: CFTimeInterval = 120
	var dictionary: [CFString: Any] = [
		kCFUserNotificationAlertHeaderKey: "MacTokenBridge",
		kCFUserNotificationAlertMessageKey: message,
		kCFUserNotificationDefaultButtonTitleKey: Strings.ok,
		kCFUserNotificationAlternateButtonTitleKey: Strings.cancel,
		kCFUserNotificationTextFieldTitlesKey: ["PIN"],
	]
	let flags = kCFUserNotificationCautionAlertLevel | CFUserNotificationSecureTextField(0)
	if offerRemember {
		// "Don't remember" first: the pop-up starts at item 0.
		dictionary[kCFUserNotificationPopUpTitlesKey] = PINRetention.allCases.map(Strings.retention)
	}
	var error: Int32 = 0
	guard let notification = CFUserNotificationCreate(nil, timeout, flags, &error, dictionary as CFDictionary) else {
		throw CancelledError(what: "PIN entry (dialog error \(error))")
	}
	var response: CFOptionFlags = 0
	let status = CFUserNotificationReceiveResponse(notification, timeout, &response)
	// The low two bits of the response say which button was pressed (or kCFUserNotificationCancelResponse).
	let button = response & 0x3
	guard status == 0, button == kCFUserNotificationDefaultResponse,
		let pin = CFUserNotificationGetResponseValue(notification, kCFUserNotificationTextFieldValuesKey, 0) as String?,
		!pin.isEmpty else {
		CFUserNotificationCancel(notification)
		throw CancelledError(what: "PIN entry")
	}
	// The response carries the selected pop-up item as CFUserNotificationPopUpSelection(n).
	let selected = Int((response >> 24) & 0xff)
	let options = PINRetention.allCases
	let retention = offerRemember && selected < options.count ? options[selected] : .never
	return (pin, retention)
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
