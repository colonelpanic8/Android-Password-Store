# Password Store

Password Store is a [`pass`](https://www.passwordstore.org/)-compatible **password** manager, **passkey** credential provider and **autofill** service for Android.

As a credential provider, it can respond to passkey creation and authentication requests from browsers and native apps. Supported **passkey types** are **EdDSA (Ed25519)**, **ES256**, and **RS256**. Passkey functionality is available on devices with Android 14 and above.

Forked from the archived [Password Store](https://github.com/android-password-store/Android-Password-Store) project.

[![GitHub workflow](https://github.com/agrahn/Android-Password-Store/workflows/Deploy%20snapshot%20builds/badge.svg)](https://github.com/agrahn/Android-Password-Store/actions)

## Download

[<img src="https://github.com/machiav3lli/oandbackupx/blob/034b226cea5c1b30eb4f6a6f313e4dadcbb0ece4/badge_github.png"
    alt="Get it on GitHub"
    height="60">](https://github.com/agrahn/Android-Password-Store/releases)
[<img src="https://fdroid.gitlab.io/artwork/badge/get-it-on.svg"
    alt="Get it on F-Droid"
    height="60">](https://f-droid.org/en/packages/app.passwordstore.agrahn)

Latest [snapshot build (APK)](https://github.com/agrahn/Android-Password-Store/releases/tag/latest) of this fork

Verification info:

- Package ID: `app.passwordstore.agrahn`
- SHA-256 hash of signing certificate (GitHub releases): `CA:3A:D7:C5:F9:90:BF:82:57:7C:EC:3B:9F:F9:E5:DB:C1:7E:05:2F:AB:C3:C7:58:8A:48:92:C4:15:67:12:90`

## Documentation

The original documentation can be found [here](https://docs.passwordstore.app) and [there](https://github.com/android-password-store/Android-Password-Store/wiki/).

To activate passkey (Android 14+) and autofill support, go to Settings → Autofill & Passkeys and choose Password Store as your preferred service. For Chrome and Chromium-based browsers, you might additionally need to enable "Autofill using another service" within the browser's own settings.

Utilising the standard `pass` file structure, passkey data is stored on the first line, followed by optional extra content, as line-oriented plain text secured by PGP encryption. Details on passkey encoding and storage are given in file [`PasskeyStorage.md`](PasskeyStorage.md).

## How-To: Transfer a PGP key to Password Store securely

### From GPG keyring
````bash
gpg --armor --gen-random 1 24 # generate a strong random password; use it in the next step
gpg --armor --export-secret-keys <ID of key used for pass> | gpg --armor --symmetric --output myKeyForPass.sec.asc
````
File `myKeyForPass.sec.asc` can be directly imported into Password Store via Settings → PGP Settings → Key Manager → <kbd>+</kbd>; enter the password from the first step when asked for the backup code.

### From OpenKeychain
1. In the main app window, select the key that you use for `pass`/Password Store from the "My Keys" list.
2. In the window that appears, tap the three-dot menu in the top right corner and select "Backup key".
3. Write down the backup code, then save the backup file to your phone.
4. Import this backup file into Password Store by navigating to Settings → PGP Settings → Key Manager → <kbd>+</kbd>, and enter the backup code when prompted.

## EVA integration

This fork (`colonelpanic8/Android-Password-Store`, branch `eva-extension`) adds an extension for the [EVA](https://github.com/colonelpanic8/eva) assistant. It installs as **Password Store (EVA)**, package `app.passwordstore.colonelpanic`, next to upstream's `app.passwordstore.agrahn`. Each copy has its own store, keys and settings.

- Releases: tags `v<upstream version>-eva.<n>` (for example `v2.0.3-eva.1`) build a signed APK and attach it to a GitHub release, which Obtainium can track. The version code is `(major×10000 + minor×100 + patch)×100 + n`.
- SHA-256 of the signing certificate: `D1:67:E4:0C:4A:AF:EB:ED:BF:11:3B:6F:1B:65:9E:A8:D2:F2:BC:D6:5E:C5:83:D3:07:60:86:71:B9:45:60:24`

### Extension service

`app.passwordstore.eva.EvaExtensionService` implements EVA's installed-app AIDL protocol v1. Only `com.colonelpanic.eva` signed with EVA's release certificate may call it. Debug builds also accept `com.colonelpanic.eva.debug` signed with the development debug key, or with the certificate whose SHA-256 digest is passed as `-PevaDebugCert=<sha256>` (such as `./gradlew assembleDebug -PevaDebugCert=$(apksigner verify --print-certs app-debug.apk | sed -n 's/.*SHA-256 digest: //p')` on EVA's debug APK); release builds ignore it. Both tools are reads:

| Tool | What it does |
| --- | --- |
| `search_entries` | Matches words against entry paths without decrypting anything. Optional `query`, `offset` and `limit` (1–200, default 50); reports `truncated` and `nextOffset`. |
| `get_credential` | Decrypts one entry (`path`) and returns the username, URL, whether it has a one-time code, and the names of its other fields. The password and the current TOTP code go only into the reply's `secrets`, which EVA hands to the model as fill-only handles. Optional `fields` (up to 6 names from `fieldNames`, matched ignoring case) adds those fields' values as secrets too, such as a card `number` or `zip` to type on a phone keypad. Offered only to EVA versions that announce the `secrets` feature. |

A requested field becomes a secret named after it: lowercased, with each run of other characters turned into `_`, prefixed `field_` if it does not start with a letter, and numbered from `_2` when the name is taken (`password` and `otp` always are). Its label is `<field> of <path>`. The reply's `fieldSecrets` maps each handed-over field to its secret name. `unavailableFields` lists the requested fields that were not handed over, with the reason `not_found`, `empty` or `too_long` (over EVA's 4,096-character limit). The text names the entry's fields whenever a requested name matched none. The rest of the reply still completes. Values never appear in the text or structured content.

Decryption never shows UI. A key without a passphrase works at any time. For a passphrase-protected key, the service uses, in order:

1. **The passphrase saved in EVA.** EVA versions that announce the `credentials` feature see a declared `passphrase` credential. EVA stores it encrypted on the phone and passes it in each `get_credential` call under the reserved `_credentials` argument. The service strips it before validating the arguments, uses it for that one decryption, then wipes its copy. It never stores, logs or echoes it. This works on a locked phone. If it is wrong, the call fails with `not_configured` and says to update it in EVA, without trying anything else.
2. **The app's own in-memory cache.** Unlock any entry in the app with **Keep passphrase until screen-off** checked; fingerprint or PIN fast unlock fills the same cache. The app forgets the passphrase whenever the screen turns off, and the cache needs a hardware-backed keystore.

With neither, `get_credential` returns `not_configured` and names both fixes.

### Intents

Both open the app's normal UI (including the app lock and passphrase prompt) and return nothing:

| Action | Extra | Opens |
| --- | --- | --- |
| `app.passwordstore.colonelpanic.action.OPEN_ENTRY` | `path`: entry path without `.gpg`, such as `github.com/alice` | That entry's decrypted view |
| `app.passwordstore.colonelpanic.action.SEARCH` | `query` (optional) | The password list with the search filled in |

```shell
adb shell am start -a app.passwordstore.colonelpanic.action.OPEN_ENTRY -p app.passwordstore.colonelpanic --es path github.com/alice
```

## Contributing

Issues and pull requests are welcome, but avoid bulky, hard to digest multi-feature contributions, especially AI-generated ones. Refer to the [Changelog](CHANGELOG.md) for the latest fixes and additions.

## Donations

If you wish to sponsor the original author, financial contributions can be made through [OpenCollective](https://opencollective.com/android-password-store).
