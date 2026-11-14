# MacTokenBridge

Use a PKCS#11 signing certificate — such as a **Certum SimplySign** cloud signature — to sign in to websites in **Chrome, Safari, Edge** and other macOS apps, not just Firefox.

On macOS, Chrome and Safari only see certificates that the system itself knows about (the keychain and smart cards). Many signature providers ship only a PKCS#11 module for the Mac, which Firefox can load but Chrome cannot. MacTokenBridge connects the two: it presents your PKCS#11 certificate to macOS as a smart card.

> **Status:** early release. Tested with Certum SimplySign (qualified certificate, RSA-3072) on macOS 26.5, signing in to JAO eCAT with Chrome, and with EC P-256 keys on SoftHSM v2. Other modules should work in principle but are untested — please report what you try.

## How it works

```
Website ──"client certificate, please"──► Chrome / Safari
Chrome ──"which certificates are there?"──► macOS (CryptoTokenKit)
macOS ──► MacTokenBridge token extension: "this one"
Chrome ──"sign the TLS handshake"──► macOS ──► token extension
token extension ──XPC──► MacTokenBridge helper ──► PKCS#11 module ──► card / cloud
```

- **Token extension** — a CryptoTokenKit *persistent token*. It registers your certificates with macOS. It runs sandboxed, so it cannot load a PKCS#11 module itself.
- **Helper** — started by launchd on demand. It loads the PKCS#11 module, asks for your PIN once, and signs. It accepts requests only from MacTokenBridge's own token extension.

Like Firefox, the helper asks for the PIN once and stays logged in until you log out, restart, or the token goes away (for SimplySign: until SimplySign Desktop disconnects).

The PIN dialog can also **remember the PIN for 1 hour or 1 day** (the default is not to remember it). While the remembered PIN is valid, the helper signs in again by itself after SimplySign Desktop reconnects, after a restart of the helper, or after you restart your Mac. See [Security](#security) before you use this.

## Requirements

- macOS 14 or later, Apple silicon or Intel.
- Your signature provider's software, including its PKCS#11 module. For SimplySign: **SimplySign Desktop**, signed in.
- An RSA or EC (ECDSA) certificate. With RSA, sites must accept RSA PKCS#1 v1.5 client signatures (see [Limitations](#limitations)).

## Install

### Disk image (recommended)

1. Download `MacTokenBridge-<version>.dmg` from [Releases](../../releases) and open it.
2. Drag **MacTokenBridge** to **Applications**, then open it from Applications. (Opened straight from the disk image, it asks you to move it first.)
3. MacTokenBridge reads the certificates from your token and shows which ones it registered. If your token is not available yet (for SimplySign: SimplySign Desktop is not signed in), sign in and click **Try Again**.
4. Open the website. Chrome asks you to choose a certificate, then MacTokenBridge asks for your PIN.

Open MacTokenBridge again whenever you get a new certificate or install a new version.

### From source

Needs the Xcode Command Line Tools (`xcode-select --install`).

```bash
git clone https://github.com/MasterRok/MacTokenBridge.git
cd MacTokenBridge
scripts/install.sh
```

This builds an ad-hoc signed copy into `~/Applications` for your user only.

### Choosing the PKCS#11 module

By default MacTokenBridge uses the first of these that exists:

| Module | Provider |
|---|---|
| `/usr/local/lib/libSimplySignPKCS.dylib` | Certum SimplySign (cloud) |
| `/Applications/proCertumSmartSign.app/Contents/MacOS/libcryptoCertum3PKCS.dylib` | Certum cryptoCertum cards |
| `/Library/OpenSC/lib/opensc-pkcs11.so` | OpenSC |

For any other module:

```bash
/Applications/MacTokenBridge.app/Contents/MacOS/MacTokenBridge install --module /path/to/pkcs11-module.dylib
```

(Use `~/Applications/...` if you installed from source.)

## Commands

```bash
MacTokenBridge status     # module, registered certificates, log location
MacTokenBridge selftest   # sign a random digest through the keychain, exactly like a browser
MacTokenBridge install    # re-read the certificates (e.g. after renewing one)
MacTokenBridge forget-pin # delete remembered PINs and log out; the next signature asks for the PIN
MacTokenBridge uninstall  # remove the token, the helper and any remembered PIN
```

The helper logs to `~/Library/Logs/MacTokenBridge.log`.

## Uninstall

```bash
/Applications/MacTokenBridge.app/Contents/MacOS/MacTokenBridge uninstall
```

Then move MacTokenBridge from Applications to the Trash.

## Security

Read this before you use a qualified signature with it.

- **While the helper is logged in, any app running as you can ask macOS to sign with your key**, without another prompt. That is how macOS treats smart cards too, but a qualified signature is legally binding. Log out of your Mac account (or restart) to end the session, and only run software you trust.
- Your PIN goes from the PIN dialog straight into the PKCS#11 module (`C_Login`). It is never logged, and it is stored only if you choose to remember it.
- **A remembered PIN** is kept in your login keychain as a generic password named "MacTokenBridge PIN", together with its expiry. It stays on this Mac (not synced to iCloud) and is not used after it expires; an expired one is deleted the next time the helper needs a PIN. A remembered PIN gets one attempt: if the token does not accept it, MacTokenBridge deletes it, does not send it again, and asks you (with one try fewer, since that attempt counted), so it cannot lock your token on its own. `forget-pin` and `uninstall` delete it.
  - The trade-off: while it is stored, the PIN itself sits on disk, protected by your login keychain. Other apps normally get a macOS keychain prompt before they can read it. A copy of MacTokenBridge built from source is ad-hoc signed: then programs you build yourself can read it without a prompt, and after every rebuild macOS asks once whether MacTokenBridge may use the stored PIN. Anyone who can unlock your Mac account can read it in Keychain Access. For a qualified signature, remember the PIN only on a Mac that only you use.
- The helper accepts XPC requests only from MacTokenBridge's own token extension, checked by code signature.
- The code is small and meant to be read: `Sources/App/PKCS11Session.swift` and `Sources/PKCS11/p11.c` handle the module; `Sources/Token/` is everything the system sees.

## Limitations

- **RSA keys sign with PKCS#1 v1.5 only, no RSA-PSS yet.** TLS 1.3 requires RSA-PSS (or ECDSA) for client certificates, so a TLS 1.3-only site will not work with an RSA key. SimplySign has no RSA-PSS at all, so this affects Firefox the same way.
- **EC keys sign with ECDSA** (`CKM_ECDSA`), which TLS 1.2 and 1.3 both accept. The module must offer `CKM_ECDSA`; MacTokenBridge hashes nothing itself and passes the digest the browser asks to sign.
- Only the first slot that holds a token is used; all its user certificates are registered.
- Tested with one provider so far.

## Troubleshooting

- **"The signing token is not available."** For SimplySign: open SimplySign Desktop and sign in again, then reload the page. SimplySign Desktop 2.10 sometimes crashes while connecting to the cloud on macOS 26; reopening it helps.
- **No certificate in Chrome's list.** Run `MacTokenBridge status`. If nothing is registered, run `MacTokenBridge install` while the token is available.
- **Anything else:** check `~/Library/Logs/MacTokenBridge.log` and open an issue with it (it contains no PINs or keys).

### Notes for developers

The SimplySign module keeps its login per calling thread: a watcher thread (`ThreadsWatchingTread`) checks callers with `pthread_kill(thread, 0)` and tears down the login and cloud connection (`pkislFinalOne`) once a caller has exited. The helper therefore makes every PKCS#11 call from one long-lived thread (`Sources/App/P11Thread.swift`). Without it, short-lived GCD worker threads made the connection drop seconds after the first signature.

### Tests

```bash
scripts/test.sh
```

Builds and runs the unit tests in `Tests/` (the pure code in `Sources/Shared`, such as converting PKCS#11's raw ECDSA signature to the DER form macOS expects).

## Building a release

```bash
APP_IDENTITY="Developer ID Application: Name (TEAMID)" scripts/package.sh
```

This builds, signs, notarizes and staples `build/MacTokenBridge-<version>.dmg`. It needs a `notarytool` keychain profile named `MacTokenBridge` (`xcrun notarytool store-credentials MacTokenBridge ...`). `SKIP_NOTARIZE=1` skips notarization for local testing.

The app icon is drawn in `Resources/Icon/*.svg`. After editing the artwork, run `scripts/icon.sh` to rebuild `Resources/App/AppIcon.icns`, and commit both.

## Support the project

MacTokenBridge is free. If it saved you time, donations are welcome. Please send each coin **only on the network listed** — anything sent on another network is lost.

| Coin | Network | Address |
|---|---|---|
| BTC | Bitcoin | `bc1qskfku5w967esarysykg0shxxvhtv032z5vfhf3` |
| USDT | TRON (TRC-20) only | `TY3Etzbx4S24R9L3tQi46MrcZtxcCicVvL` |
| ETH | Ethereum | `0x36803D595ae71E28dD6478daB49602Ba0178Aed1` |
| SOL | Solana | `6H5waHz1g4Tqffrdca3hzG1JTGfHPqov7phUiwKwDJVy` |

## License

MIT — see [LICENSE](LICENSE). `Vendor/pkcs11.h` comes from [p11-kit](https://github.com/p11-glue/p11-kit) and carries its own permissive notice.

MacTokenBridge is an independent project, not affiliated with or endorsed by Certum, Asseco Data Systems, or any other signature provider. SimplySign is a trademark of its owner.
