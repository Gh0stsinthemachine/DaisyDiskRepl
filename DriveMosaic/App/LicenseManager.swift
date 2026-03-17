import Foundation
import CryptoKit

/// Manages DriveMosaic Pro license state.
/// Uses LemonSqueezy license key validation with HMAC-protected local caching.
@Observable
@MainActor
final class LicenseManager {
    static let shared = LicenseManager()

    // MARK: - Observable State

    var isPro: Bool = false
    var validationState: ValidationState = .none

    enum ValidationState: Equatable {
        case none
        case validating
        case valid
        case invalid(String)
    }

    // MARK: - Storage Keys

    private static let keyLicenseKey = "dm_license_key"
    private static let keyLicenseToken = "dm_license_token"
    private static let keyInstanceID = "dm_instance_id"

    // MARK: - HMAC Secret (obfuscated — not a server secret, just anti-tamper)

    private static let hmacSeed: [UInt8] = [
        0x44, 0x72, 0x69, 0x76, 0x65, 0x4D, 0x6F, 0x73,
        0x61, 0x69, 0x63, 0x50, 0x72, 0x6F, 0x56, 0x31,
        0x42, 0x6C, 0x61, 0x63, 0x6B, 0x43, 0x6C, 0x6F,
        0x75, 0x64, 0x4C, 0x4C, 0x43, 0x32, 0x30, 0x32
    ]

    // MARK: - LemonSqueezy

    static let purchaseURL = URL(string: "https://blackcloud.lemonsqueezy.com/checkout/buy/66fde7fe-0a10-4c9b-af49-1defcf4cc8a6")!

    // MARK: - Init

    private init() {
        // Restore cached validation — verify HMAC integrity
        let storedKey = UserDefaults.standard.string(forKey: Self.keyLicenseKey) ?? ""
        let storedToken = UserDefaults.standard.string(forKey: Self.keyLicenseToken) ?? ""

        if !storedKey.isEmpty && !storedToken.isEmpty && verifyToken(key: storedKey, token: storedToken) {
            isPro = true
            validationState = .valid
        } else if !storedKey.isEmpty {
            // Key exists but token is missing/invalid — tampered or legacy. Clear it.
            UserDefaults.standard.removeObject(forKey: Self.keyLicenseKey)
            UserDefaults.standard.removeObject(forKey: Self.keyLicenseToken)
        }
    }

    // MARK: - Public API

    var storedKey: String {
        UserDefaults.standard.string(forKey: Self.keyLicenseKey) ?? ""
    }

    /// Activate a license key via LemonSqueezy API.
    func activate(key: String) async {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            validationState = .invalid("Please enter a license key.")
            return
        }

        validationState = .validating

        // Try LemonSqueezy API
        do {
            let valid = try await validateWithLemonSqueezy(key: trimmed)
            if valid {
                storeValidation(key: trimmed)
            } else {
                validationState = .invalid("Invalid license key. Please check and try again.")
            }
        } catch {
            validationState = .invalid("Could not verify key. Check your connection and try again.")
        }
    }

    /// Remove stored license and revert to Free
    func deactivate() {
        UserDefaults.standard.removeObject(forKey: Self.keyLicenseKey)
        UserDefaults.standard.removeObject(forKey: Self.keyLicenseToken)
        UserDefaults.standard.removeObject(forKey: Self.keyInstanceID)
        isPro = false
        validationState = .none
    }

    // MARK: - HMAC Token Generation & Verification

    /// Generate an HMAC token from the license key + machine-specific data
    private func generateToken(key: String) -> String {
        let instanceID = getOrCreateInstanceID()
        let payload = "dm:\(key):\(instanceID)"
        let hmacKey = SymmetricKey(data: Self.hmacSeed)
        let signature = HMAC<SHA256>.authenticationCode(for: Data(payload.utf8), using: hmacKey)
        return Data(signature).base64EncodedString()
    }

    /// Verify that a stored token matches the expected HMAC for a given key
    private func verifyToken(key: String, token: String) -> Bool {
        let expected = generateToken(key: key)
        // Constant-time comparison to prevent timing attacks
        guard expected.count == token.count else { return false }
        var result: UInt8 = 0
        for (a, b) in zip(expected.utf8, token.utf8) {
            result |= a ^ b
        }
        return result == 0
    }

    // MARK: - Private

    private func storeValidation(key: String) {
        let token = generateToken(key: key)
        UserDefaults.standard.set(key, forKey: Self.keyLicenseKey)
        UserDefaults.standard.set(token, forKey: Self.keyLicenseToken)
        isPro = true
        validationState = .valid
    }

    /// Validate license key against LemonSqueezy activation API.
    /// This is a public endpoint — no API key required.
    private func validateWithLemonSqueezy(key: String) async throws -> Bool {
        let url = URL(string: "https://api.lemonsqueezy.com/v1/licenses/activate")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        // Get or create a stable instance ID for this machine
        let instanceID = getOrCreateInstanceID()

        let body: [String: String] = [
            "license_key": key,
            "instance_name": instanceID
        ]
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse else {
            throw URLError(.badServerResponse)
        }

        // LemonSqueezy returns 200 for valid, 400/404 for invalid
        if httpResponse.statusCode == 200 {
            // Parse response to confirm activation — fail closed on unparseable response
            if let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let activated = json["activated"] as? Bool {
                return activated
            }
            // If parsing fails, do NOT assume valid
            return false
        }

        return false
    }

    /// Get or create a stable machine identifier for license activation
    private func getOrCreateInstanceID() -> String {
        if let existing = UserDefaults.standard.string(forKey: Self.keyInstanceID) {
            return existing
        }
        let id = "DriveMosaic-\(ProcessInfo.processInfo.hostName)"
        UserDefaults.standard.set(id, forKey: Self.keyInstanceID)
        return id
    }
}
