import Foundation
import CryptoKit
import IOKit
import LocalAuthentication
import Security

// Irreducibly Swift: Apple exposes Secure Enclave key persistence only through
// CryptoKit's dataRepresentation. Everything else lives in Rust.

private func store(_ data: Data, _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    if data.count > cap { return -2 }
    data.copyBytes(to: buf, count: data.count)
    return data.count
}

private func complain(_ what: String) {
    FileHandle.standardError.write("keywardd: \(what)\n".data(using: .utf8)!)
}

/// policy: 0 = no auth, 1 = user presence, 2 = current biometry set. 3, the sign-in
/// key, is two keys and is made by `SignInKey.generate`.
///
/// A `none` key is the one meant for unattended signing, so it stays usable while the
/// screen is locked: a WhenUnlocked key refuses every signature then with -25308
/// (errSecInteractionNotAllowed), which is how agents pushing from a locked Mac failed.
private func accessControl(_ policy: Int32) -> SecAccessControl? {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if policy == 1 { flags.insert(.userPresence) }
    if policy == 2 { flags.insert(.biometryCurrentSet) }
    let accessible = policy == 0
        ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
    return SecAccessControlCreateWithFlags(nil, accessible, flags, nil)
}

/// An authentication only carries over within a single LAContext — a fresh context
/// per signature always re-authenticates. Holding one for as long as the approval
/// lasts is what actually turns "once per host" into "once per window", and "once
/// per signature" into "once per sign-in". The enclave has the last word on a key it
/// guards itself: a presence or biometry key is asked for again about ten minutes
/// after each authentication, whatever is held here.
///
/// One context per scope, keyed by the daemon. A single shared context meant two
/// agents working in two repositories evicted each other: every request from one
/// dropped the other's approval, so alternating fetches prompted every time.
///
/// Nothing here keeps time. The daemon owns the only clock and calls `forget` when
/// an approval runs out. A second clock in here ran out first — by as long as the
/// prompt had been on screen, and by however long the Mac had slept — and a request
/// in that gap prompted while the daemon logged it as reused.
private final class ContextCache {
    static let shared = ContextCache()
    private let lock = NSLock()
    private var held: [String: LAContext] = [:]
    /// What a sign-in key's Touch ID released, per scope. This is what a sign-in is
    /// for that kind of key: the enclave signs for whoever presents it, so it lives
    /// here, in memory, and nowhere else.
    private var secrets: [String: Data] = [:]

    func secret(scope: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return secrets[scope]
    }

    func keep(scope: String, secret: Data) {
        lock.lock()
        secrets[scope] = secret
        lock.unlock()
    }

    /// Overwrite before letting go, for what that is worth to a value that has been
    /// copied out for every signature. Call with the lock held.
    private func wipe(_ scope: String) {
        if let n = secrets[scope]?.count {
            secrets[scope]?.resetBytes(in: 0..<n)
        }
        secrets[scope] = nil
    }

    /// Every scope at once: the screen locked.
    func forgetAll() {
        lock.lock()
        held.removeAll()
        for scope in Array(secrets.keys) { wipe(scope) }
        lock.unlock()
    }

    /// Returns the context for `scope` and whether it is new. A new context has to
    /// be authenticated explicitly before it signs: the prompt the enclave raises on
    /// its own does not start the reuse clock, so the next request in the window
    /// prompted a second time and only the third was silent.
    ///
    /// With `hold` the context is kept, including on the request that opens the
    /// window: an approval given outside every scope used to build a context that
    /// was never kept, so the very next in-scope request prompted again. The daemon
    /// calls `forget` first when no live approval covers the request.
    ///
    /// `unlockReuse` is macOS's own reuse: a Touch ID unlock of the Mac within that
    /// many seconds (300 at most) answers the prompt without it being shown.
    func take(scope: String, hold: Bool, unlockReuse: Double) -> (LAContext, Bool) {
        lock.lock()
        defer { lock.unlock() }
        if hold, let c = held[scope] {
            return (c, false)
        }
        let c = LAContext()
        if unlockReuse > 0 {
            c.touchIDAuthenticationAllowableReuseDuration =
                min(unlockReuse, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        }
        if hold { held[scope] = c }
        return (c, true)
    }

    /// Drop the cached context for `scope` so its next request authenticates again.
    func forget(scope: String) {
        lock.lock()
        held[scope] = nil
        wipe(scope)
        lock.unlock()
    }
}

/// One explicit authentication on `ctx`, with our own text on the sheet. What `ctx`
/// does next rides it without a second prompt. deviceOwnerAuthentication is Touch
/// ID with the password as fallback, which is what a presence key accepts.
private func authenticate(_ ctx: LAContext, _ text: String) -> Bool {
    let done = DispatchSemaphore(value: 0)
    var ok = false
    var why: Error?
    ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: text.isEmpty ? "sign an SSH request" : text) { success, error in
        ok = success
        why = error
        done.signal()
    }
    done.wait()
    if !ok {
        complain("authentication failed: \(why.map { String(describing: $0) } ?? "unknown")")
    }
    return ok
}

// MARK: - The sign-in key

/// A key that costs one Touch ID per sign-in, enforced by the enclave rather than by
/// this daemon's good behaviour.
///
/// A presence key cannot do that: the enclave accepts one authentication for about
/// ten minutes and then asks again, whatever context is held. A `none` key can, but
/// only because nothing guards it: any process that reads the handle may sign.
///
/// So this is two keys. The signing key has no presence requirement; instead the
/// enclave uses it only for a caller that presents a secret (an application
/// password). The unlock key does have one, and all it ever does is reproduce that
/// secret, by key agreement with a pair whose private half was thrown away when the
/// key was made. One Touch ID releases the secret, the daemon holds it for as long as
/// the sign-in lasts, and a copy of the handle signs nothing without a Touch ID of
/// its own.
///
/// The secret is the same for as long as the key exists. That is the price of asking
/// once: a Touch ID given to the wrong caller is given for good, where a presence key
/// would have cost ten minutes.
///
/// Both halves are usable only while the Mac is unlocked, and the daemon drops the
/// secret when the screen locks.
private struct SignInKey {
    static let magic = Data("keyward sign-in key 1\n".utf8)

    /// Enclave handle of the signing key.
    let signing: Data
    /// Enclave handle of the unlock key.
    let unlock: Data
    /// Public half of the thrown-away pair the unlock key agrees with.
    let peer: Data
    /// Public half of the signing key, so listing it never needs the secret.
    let pub: Data

    init(signing: Data, unlock: Data, peer: Data, pub: Data) {
        self.signing = signing
        self.unlock = unlock
        self.peer = peer
        self.pub = pub
    }

    /// nil for anything that is not one of these, which is how a plain enclave
    /// handle is told apart.
    init?(_ d: Data) {
        guard d.starts(with: Self.magic) else { return nil }
        var rest = d.dropFirst(Self.magic.count)
        var parts: [Data] = []
        while !rest.isEmpty {
            guard rest.count >= 4 else { return nil }
            let n = rest.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            rest = rest.dropFirst(4)
            guard rest.count >= n else { return nil }
            parts.append(Data(rest.prefix(n)))
            rest = rest.dropFirst(n)
        }
        guard parts.count == 4 else { return nil }
        self.init(signing: parts[0], unlock: parts[1], peer: parts[2], pub: parts[3])
    }

    var data: Data {
        var out = Self.magic
        for p in [signing, unlock, peer, pub] {
            out.append(contentsOf: [24, 16, 8, 0].map { UInt8(truncatingIfNeeded: p.count >> $0) })
            out.append(p)
        }
        return out
    }

    private static func password(_ agreed: SharedSecret) -> Data {
        agreed.hkdfDerivedSymmetricKey(using: SHA256.self, salt: Data(),
                                       sharedInfo: Data("keyward sign-in key".utf8),
                                       outputByteCount: 32)
            .withUnsafeBytes { Data($0) }
    }

    /// The context a signature is made with: it carries the secret and can never
    /// raise a prompt, so a wrong or missing secret is a refusal and nothing else.
    private static func bearing(_ secret: Data) -> LAContext? {
        let c = LAContext()
        c.interactionNotAllowed = true
        return c.setCredential(secret, type: .applicationPassword) ? c : nil
    }

    static func generate() -> SignInKey? {
        guard let guarded = SecAccessControlCreateWithFlags(
                  nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], nil),
              let secretBound = SecAccessControlCreateWithFlags(
                  nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .applicationPassword], nil)
        else { return nil }
        do {
            let unlock = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: guarded)
            // The other side of the agreement exists for this one call. Its public
            // half is kept and its private half is not, so from here on the secret
            // can only be reproduced inside the enclave, behind a Touch ID.
            let peer = P256.KeyAgreement.PrivateKey()
            let secret = password(try peer.sharedSecretFromKeyAgreement(with: unlock.publicKey))
            guard let ctx = bearing(secret) else { return nil }
            let signing = try SecureEnclave.P256.Signing.PrivateKey(
                accessControl: secretBound, authenticationContext: ctx)
            let made = SignInKey(signing: signing.dataRepresentation, unlock: unlock.dataRepresentation,
                                 peer: peer.publicKey.x963Representation,
                                 pub: signing.publicKey.x963Representation)
            // The whole key rests on the enclave refusing the signing half to a caller
            // without the secret, and the secret to a caller nobody authenticated.
            // Nothing above would notice if it did not: the result would be a `none`
            // key wearing this one's name. So both are tried before it is kept.
            guard made.opens(with: secret),
                  !made.opens(with: Data(secret.map { ~$0 })),
                  (try? SecureEnclave.P256.Signing.PrivateKey(
                      dataRepresentation: made.signing, authenticationContext: refusing())
                      .signature(for: probe)) == nil,
                  (try? made.secret(refusing())) == nil
            else {
                complain("sign-in key generation failed: the enclave does not hold the key to its secret")
                return nil
            }
            return made
        } catch {
            complain("sign-in key generation failed: \(error)")
            return nil
        }
    }

    private static let probe = Data("keyward sign-in key check".utf8)

    private static func refusing() -> LAContext {
        let c = LAContext()
        c.interactionNotAllowed = true
        return c
    }

    /// Whether `secret` makes the signing key sign, checked against its public half.
    func opens(with secret: Data) -> Bool {
        guard let sig = try? sign(Self.probe, with: secret),
              let key = try? P256.Signing.PublicKey(x963Representation: pub),
              let parsed = try? P256.Signing.ECDSASignature(rawRepresentation: sig)
        else { return false }
        return key.isValidSignature(parsed, for: Self.probe)
    }

    /// The Touch ID. `ctx` is either already authenticated, or the enclave raises
    /// its own prompt on it.
    func secret(_ ctx: LAContext) throws -> Data {
        let k = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: unlock, authenticationContext: ctx)
        let other = try P256.KeyAgreement.PublicKey(x963Representation: peer)
        return Self.password(try k.sharedSecretFromKeyAgreement(with: other))
    }

    func sign(_ message: Data, with secret: Data) throws -> Data {
        guard let ctx = Self.bearing(secret) else {
            throw LAError(.invalidContext)
        }
        defer { ctx.invalidate() }
        let k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: signing, authenticationContext: ctx)
        return try k.signature(for: message).rawRepresentation
    }
}

// The key handle in the login keychain instead of a file. A keychain item is readable
// without a prompt only by the application that created it, matched by code signature,
// so a handle stored by keywardd is not a file any process running as the user can
// read and use. That is what makes a presence-free enclave key acceptable: the daemon,
// and the approval window it enforces, become the only way to the key.
private let kcService = "dev.danielsol.keyward"
private let kcAccount = "enclave-key"

@_cdecl("kwse_keychain_load")
public func kwse_keychain_load(_ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let q: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: kcService,
        kSecAttrAccount as String: kcAccount,
        kSecReturnData as String: true,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var out: CFTypeRef?
    let st = SecItemCopyMatching(q as CFDictionary, &out)
    if st == errSecItemNotFound { return 0 }
    guard st == errSecSuccess, let d = out as? Data else {
        FileHandle.standardError.write("keywardd: keychain read failed: \(st)\n".data(using: .utf8)!)
        return -1
    }
    return store(d, buf, cap)
}

@_cdecl("kwse_keychain_store")
public func kwse_keychain_store(_ blob: UnsafePointer<UInt8>, _ len: Int, _ force: Int32) -> Int32 {
    let base: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: kcService,
        kSecAttrAccount as String: kcAccount,
    ]
    if force == 1 { SecItemDelete(base as CFDictionary) }
    var add = base
    add[kSecValueData as String] = Data(bytes: blob, count: len)
    add[kSecAttrLabel as String] = "Keyward Secure Enclave key handle"
    let st = SecItemAdd(add as CFDictionary, nil)
    if st == errSecDuplicateItem { return 2 }
    if st != errSecSuccess {
        FileHandle.standardError.write("keywardd: keychain write failed: \(st)\n".data(using: .utf8)!)
        return -1
    }
    return 0
}

/// Drop the held authentication for one scope: its next signature prompts.
@_cdecl("kwse_forget")
public func kwse_forget(_ scope: UnsafePointer<CChar>) {
    ContextCache.shared.forget(scope: String(cString: scope))
}

/// Drop every held authentication: the next signature anywhere prompts.
@_cdecl("kwse_forget_all")
public func kwse_forget_all() {
    ContextCache.shared.forgetAll()
}

/// Whether this user's screen is locked, read from the record `ioreg` shows as
/// IOConsoleUsers: 0 unlocked and at the console, 1 locked, 2 not at the console,
/// 3 when the record cannot be read. Everything but 0 bars a sign-in key: a sign-in
/// must not outlive a lock nobody could see.
@_cdecl("kwse_screen_locked")
public func kwse_screen_locked() -> Int32 {
    let root = IORegistryGetRootEntry(kIOMainPortDefault)
    defer { IOObjectRelease(root) }
    guard let sessions = IORegistryEntryCreateCFProperty(root, "IOConsoleUsers" as CFString, kCFAllocatorDefault, 0)?
              .takeRetainedValue() as? [[String: Any]]
    else { return 3 }
    let mine = sessions.filter { ($0["kCGSSessionUserIDKey"] as? Int) == Int(getuid()) }
    if mine.isEmpty { return 3 }
    if mine.contains(where: { $0["CGSSessionScreenIsLocked"] as? Bool == true }) { return 1 }
    return mine.contains(where: { $0["kCGSSessionOnConsoleKey"] as? Bool == true }) ? 0 : 2
}

@_cdecl("kwse_available")
public func kwse_available() -> Int32 { SecureEnclave.isAvailable ? 1 : 0 }

@_cdecl("kwse_generate")
public func kwse_generate(_ policy: Int32, _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    if policy == 3 {
        guard let k = SignInKey.generate() else { return -1 }
        return store(k.data, buf, cap)
    }
    guard let ac = accessControl(policy) else { return -1 }
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: ac) else { return -1 }
    return store(k.dataRepresentation, buf, cap)
}

/// 1 for a sign-in key, 0 for a plain enclave handle.
@_cdecl("kwse_kind")
public func kwse_kind(_ blob: UnsafePointer<UInt8>, _ blobLen: Int) -> Int32 {
    SignInKey(Data(bytes: blob, count: blobLen)) == nil ? 0 : 1
}

/// One real sign-in with a sign-in key, made before the key is written anywhere: 0
/// when the Touch ID released a secret that the signing key accepts. The secret a new
/// key was made with came from the half of the agreement that is then thrown away,
/// and only this proves the enclave's half arrives at the same one. A key that failed
/// here would be authorised everywhere and open for nobody.
@_cdecl("kwse_check")
public func kwse_check(_ blob: UnsafePointer<UInt8>, _ blobLen: Int, _ reason: UnsafePointer<CChar>) -> Int32 {
    guard let k = SignInKey(Data(bytes: blob, count: blobLen)) else { return -1 }
    let text = String(cString: reason)
    let ctx = LAContext()
    ctx.localizedReason = text
    guard authenticate(ctx, text) else { return -3 }
    defer { ctx.invalidate() }
    do {
        return k.opens(with: try k.secret(ctx)) ? 0 : -2
    } catch {
        complain("sign-in failed: \(error)")
        return -3
    }
}

@_cdecl("kwse_public")
public func kwse_public(_ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                        _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let d = Data(bytes: blob, count: blobLen)
    if let k = SignInKey(d) { return store(k.pub, buf, cap) }
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d) else { return -1 }
    return store(k.publicKey.x963Representation, buf, cap)
}

/// A signature with a sign-in key. With nothing held for `scope` this is the sign-in:
/// one Touch ID releases the secret, which is kept when `hold` says an approval is
/// opening. With it held, the signature needs nothing from anybody.
///
/// `riding` is a request the daemon counted as covered by a sign-in. Finding nothing
/// held, it fails with -4 and asks nobody: the sign-in ended under it, and the sheet
/// it would raise names one action while opening a sign-in.
private func signIn(_ k: SignInKey, _ message: Data, _ text: String, hold: Bool, unlockReuse: Double,
                    scope: String, approve: Bool, riding: Bool,
                    _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    var secret = hold ? ContextCache.shared.secret(scope: scope) : nil
    if secret == nil {
        if riding { return -4 }
        let ctx = LAContext()
        if unlockReuse > 0 {
            ctx.touchIDAuthenticationAllowableReuseDuration =
                min(unlockReuse, LATouchIDAuthenticationMaximumAllowableReuseDuration)
        }
        if !text.isEmpty { ctx.localizedReason = text }
        if approve && !authenticate(ctx, text) { return -3 }
        do {
            secret = try k.secret(ctx)
        } catch {
            complain("sign-in failed: \(error)")
            return -3
        }
        // The authentication has done the one thing it was for.
        ctx.invalidate()
        if hold, let secret { ContextCache.shared.keep(scope: scope, secret: secret) }
    }
    guard let secret else { return -1 }
    do {
        return store(try k.sign(message, with: secret), buf, cap)
    } catch {
        complain("enclave signature failed: \(error)")
        return -3
    }
}

@_cdecl("kwse_sign")
public func kwse_sign(_ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                      _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                      _ reason: UnsafePointer<CChar>?,
                      _ hold: Int32,
                      _ unlockReuseSeconds: Double,
                      _ scope: UnsafePointer<CChar>,
                      _ approve: Int32,
                      _ riding: Int32,
                      _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let d = Data(bytes: blob, count: blobLen)
    let key = String(cString: scope)
    var text = ""
    if let reason, let t = String(validatingUTF8: reason), !t.isEmpty {
        // This is the whole point: Keyward writes the Touch ID prompt, so it can
        // name the commit or the host instead of saying "a request from launchd".
        text = t
    }
    if let k = SignInKey(d) {
        return signIn(k, Data(bytes: msg, count: msgLen), text, hold: hold != 0,
                      unlockReuse: unlockReuseSeconds, scope: key, approve: approve != 0,
                      riding: riding != 0, buf, cap)
    }
    // Consecutive signatures under one approval share one authentication, so a
    // loop over the fleet asks once rather than once per host.
    let (ctx, fresh) = ContextCache.shared.take(scope: key, hold: hold != 0, unlockReuse: unlockReuseSeconds)
    if !text.isEmpty { ctx.localizedReason = text }
    // One explicit authentication, which the held context then carries; the
    // signature below rides it without a second prompt.
    if fresh && approve != 0 && !authenticate(ctx, text) {
        ContextCache.shared.forget(scope: key)
        return -3
    }
    let k: SecureEnclave.P256.Signing.PrivateKey
    do {
        k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d, authenticationContext: ctx)
    } catch {
        complain("enclave key load failed: \(error)")
        return -1
    }
    let sig: P256.Signing.ECDSASignature
    do {
        sig = try k.signature(for: Data(bytes: msg, count: msgLen))
    } catch {
        // The daemon maps this to "declined or authentication failed"; the log keeps the
        // real reason, which is what tells a stale grant from a user's cancel.
        complain("enclave signature failed: \(error)")
        return -3
    }
    return store(sig.rawRepresentation, buf, cap)   // r||s, 64 bytes
}
