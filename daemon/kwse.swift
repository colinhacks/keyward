import Foundation
import CryptoKit
import LocalAuthentication
import Security

// Irreducibly Swift: Apple exposes Secure Enclave key persistence only through
// CryptoKit's dataRepresentation. Everything else lives in Rust.

private func store(_ data: Data, _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    if data.count > cap { return -2 }
    data.copyBytes(to: buf, count: data.count)
    return data.count
}

/// policy: 0 = no auth, 1 = user presence, 2 = current biometry set
private func accessControl(_ policy: Int32) -> SecAccessControl? {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if policy == 1 { flags.insert(.userPresence) }
    if policy == 2 { flags.insert(.biometryCurrentSet) }
    return SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, nil)
}

/// A reuse window only has effect within a single LAContext — a fresh context
/// per signature always re-authenticates. Holding one for the length of the
/// window is what actually turns "once per host" into "once per window".
private final class ContextCache {
    static let shared = ContextCache()
    private let lock = NSLock()
    private var ctx: LAContext?
    private var born = Date.distantPast

    /// Returns the context and whether it is new. A new context has to be
    /// authenticated explicitly before it signs: the prompt the enclave raises on
    /// its own does not start the reuse clock, so the next request in the window
    /// prompted a second time and only the third was silent.
    ///
    /// The context is cached whenever a window exists, including on the request
    /// that opens it: an approval given outside every scope used to build a
    /// context that was never kept, so the very next in-scope request prompted
    /// again. The daemon calls `forget` first when the request is out of scope.
    func take(reuse: Double) -> (LAContext, Bool) {
        lock.lock()
        defer { lock.unlock() }
        if reuse > 0, let c = ctx, Date().timeIntervalSince(born) < reuse {
            return (c, false)
        }
        let c = LAContext()
        if reuse > 0 {
            c.touchIDAuthenticationAllowableReuseDuration =
                min(reuse, LATouchIDAuthenticationMaximumAllowableReuseDuration)
            ctx = c
            born = Date()
        } else {
            ctx = nil
        }
        return (c, true)
    }

    /// Drop the cached context so the next request authenticates again.
    func forget() {
        lock.lock()
        ctx = nil
        lock.unlock()
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

/// Drop the cached authentication: the next signature prompts whatever the window.
@_cdecl("kwse_forget")
public func kwse_forget() {
    ContextCache.shared.forget()
}

@_cdecl("kwse_available")
public func kwse_available() -> Int32 { SecureEnclave.isAvailable ? 1 : 0 }

@_cdecl("kwse_generate")
public func kwse_generate(_ policy: Int32, _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    guard let ac = accessControl(policy) else { return -1 }
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(accessControl: ac) else { return -1 }
    return store(k.dataRepresentation, buf, cap)
}

@_cdecl("kwse_public")
public func kwse_public(_ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                        _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let d = Data(bytes: blob, count: blobLen)
    guard let k = try? SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d) else { return -1 }
    return store(k.publicKey.x963Representation, buf, cap)
}

@_cdecl("kwse_sign")
public func kwse_sign(_ blob: UnsafePointer<UInt8>, _ blobLen: Int,
                      _ msg: UnsafePointer<UInt8>, _ msgLen: Int,
                      _ reason: UnsafePointer<CChar>?,
                      _ reuseSeconds: Double,
                      _ buf: UnsafeMutablePointer<UInt8>, _ cap: Int) -> Int {
    let d = Data(bytes: blob, count: blobLen)
    // Consecutive signatures within the window share one authentication, so a
    // loop over the fleet asks once rather than once per host.
    let (ctx, fresh) = ContextCache.shared.take(reuse: reuseSeconds)
    var text = ""
    if let reason, let t = String(validatingUTF8: reason), !t.isEmpty {
        // This is the whole point: Keyward writes the Touch ID prompt, so it can
        // name the commit or the host instead of saying "a request from launchd".
        ctx.localizedReason = t
        text = t
    }
    if fresh {
        // One explicit authentication, which the reuse window then honours; the
        // signature below rides it without a second prompt. deviceOwnerAuthentication
        // matches the key's presence policy (Touch ID, password as fallback).
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
            ContextCache.shared.forget()
            FileHandle.standardError.write("keywardd: authentication failed: \(why.map { String(describing: $0) } ?? "unknown")\n".data(using: .utf8)!)
            return -3
        }
    }
    let k: SecureEnclave.P256.Signing.PrivateKey
    do {
        k = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: d, authenticationContext: ctx)
    } catch {
        FileHandle.standardError.write("keywardd: enclave key load failed: \(error)\n".data(using: .utf8)!)
        return -1
    }
    let sig: P256.Signing.ECDSASignature
    do {
        sig = try k.signature(for: Data(bytes: msg, count: msgLen))
    } catch {
        // The daemon maps this to "declined or authentication failed"; the log keeps the
        // real reason, which is what tells a stale grant from a user's cancel.
        FileHandle.standardError.write("keywardd: enclave signature failed: \(error)\n".data(using: .utf8)!)
        return -3
    }
    return store(sig.rawRepresentation, buf, cap)   // r||s, 64 bytes
}
