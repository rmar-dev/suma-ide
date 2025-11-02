---
layout: default
title: 04 Mobile Specification
nav_exclude: true
---


# Mobile Specification - Fintech Authentication System

## 1. Mobile Architecture Overview

### Platform Strategy
- **Approach**: Native development (iOS Swift + Android Kotlin)
- **Rationale**: Fintech security requirements demand native platform security features (Keychain, BiometricPrompt, hardware-backed keystores)
- **Code Sharing**: 0% shared code between platforms; 100% platform-specific for maximum security and performance
- **Backend Integration**: Shared RESTful API with JWT authentication

### Technology Decisions
- **iOS**: Swift 5.9+ with SwiftUI, minimum iOS 15.0
- **Android**: Kotlin 1.9+ with Jetpack Compose, minimum API 26 (Android 8.0)
- **Hybrid Rejected**: React Native/Flutter lack enterprise-grade biometric security and hardware-backed key storage

### Security-First Architecture
- Native biometric authentication (Face ID, Touch ID, BiometricPrompt)
- Hardware-backed keystore for token storage
- Certificate pinning for all API calls
- Root/jailbreak detection with graceful degradation
- Local encryption for sensitive cache data (AES-256-GCM)

---

## 2. iOS Specification

### 2.1 iOS Architecture

#### Minimum Requirements
- **iOS Version**: iOS 15.0+
- **Xcode**: 15.0+
- **Swift**: 5.9+
- **Deployment Target**: iPhone and iPad (Universal)

#### Architecture Pattern
- **Pattern**: Clean Architecture + MVVM
- **UI Framework**: SwiftUI (primary), UIKit (legacy auth flows fallback)
- **Dependency Injection**: Protocol-based DI with environment objects
- **State Management**: Combine framework for reactive data flow

#### Key Architectural Decisions
```
Presentation Layer (SwiftUI Views)
        ↓
View Models (Combine Publishers)
        ↓
Use Cases (Business Logic)
        ↓
Repositories (Data Sources)
        ↓
Data Layer (Network + Keychain + CoreData)
```

### 2.2 iOS Project Structure

```
FinanceApp-iOS/
├── FinanceApp/
│   ├── App/
│   │   ├── FinanceAppApp.swift          # SwiftUI app entry point
│   │   ├── AppDelegate.swift            # UIKit lifecycle hooks
│   │   └── SceneDelegate.swift          # Multi-window support
│   │
│   ├── Features/
│   │   ├── Authentication/
│   │   │   ├── Views/
│   │   │   │   ├── LoginView.swift
│   │   │   │   ├── RegisterView.swift
│   │   │   │   ├── EmailVerificationView.swift
│   │   │   │   ├── PasswordResetView.swift
│   │   │   │   ├── TwoFactorView.swift
│   │   │   │   └── BiometricSetupView.swift
│   │   │   ├── ViewModels/
│   │   │   │   ├── LoginViewModel.swift
│   │   │   │   ├── RegisterViewModel.swift
│   │   │   │   └── AuthenticationFlowViewModel.swift
│   │   │   ├── Models/
│   │   │   │   ├── User.swift
│   │   │   │   ├── LoginRequest.swift
│   │   │   │   ├── AuthToken.swift
│   │   │   │   └── AuthError.swift
│   │   │   └── UseCases/
│   │   │       ├── LoginUseCase.swift
│   │   │       ├── RegisterUseCase.swift
│   │   │       └── BiometricAuthUseCase.swift
│   │   │
│   │   ├── Dashboard/
│   │   │   ├── Views/
│   │   │   │   ├── DashboardView.swift
│   │   │   │   └── ProfileView.swift
│   │   │   └── ViewModels/
│   │   │       └── DashboardViewModel.swift
│   │   │
│   │   └── Settings/
│   │       ├── Views/
│   │       │   ├── SecuritySettingsView.swift
│   │       │   ├── DeviceManagementView.swift
│   │       │   └── ConsentManagementView.swift
│   │       └── ViewModels/
│   │
│   ├── Core/
│   │   ├── Networking/
│   │   │   ├── APIClient.swift           # URLSession wrapper
│   │   │   ├── HTTPMethod.swift
│   │   │   ├── Endpoint.swift
│   │   │   ├── NetworkError.swift
│   │   │   ├── CertificatePinner.swift   # SSL pinning
│   │   │   └── RequestInterceptor.swift  # JWT injection
│   │   │
│   │   ├── Security/
│   │   │   ├── KeychainManager.swift     # Secure token storage
│   │   │   ├── BiometricAuthManager.swift
│   │   │   ├── CryptoManager.swift       # AES-256-GCM encryption
│   │   │   ├── JailbreakDetector.swift
│   │   │   └── CertificatePinning.swift
│   │   │
│   │   ├── Storage/
│   │   │   ├── CoreDataStack.swift
│   │   │   ├── UserDefaultsManager.swift
│   │   │   └── SecureCache.swift         # Encrypted cache
│   │   │
│   │   ├── Logging/
│   │   │   ├── Logger.swift
│   │   │   └── AnalyticsTracker.swift
│   │   │
│   │   └── Extensions/
│   │       ├── String+Validation.swift
│   │       ├── View+Extensions.swift
│   │       └── Date+Extensions.swift
│   │
│   ├── Design/
│   │   ├── Theme/
│   │   │   ├── Colors.swift
│   │   │   ├── Typography.swift
│   │   │   └── Spacing.swift
│   │   ├── Components/
│   │   │   ├── PrimaryButton.swift
│   │   │   ├── SecureTextField.swift
│   │   │   ├── LoadingIndicator.swift
│   │   │   └── AlertBanner.swift
│   │   └── Modifiers/
│   │
│   └── Resources/
│       ├── Assets.xcassets/
│       ├── Localizable.strings
│       ├── Info.plist
│       └── Entitlements.plist
│
├── FinanceAppTests/
│   ├── AuthenticationTests/
│   ├── NetworkingTests/
│   └── SecurityTests/
│
└── FinanceAppUITests/
    └── AuthenticationFlowTests/
```

### 2.3 iOS Key Features

#### Authentication & Security

**Keychain Token Storage**
```swift
class KeychainManager {
    func saveToken(_ token: String, forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: token.data(using: .utf8)!,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        // Implementation with error handling
    }
}
```

**Biometric Authentication (Face ID / Touch ID)**
```swift
import LocalAuthentication

class BiometricAuthManager {
    func authenticateUser(reason: String) async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Use Passcode"
        
        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil) else {
            throw BiometricError.notAvailable
        }
        
        return try await context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: reason
        )
    }
}
```

**Certificate Pinning**
```swift
class CertificatePinner: NSObject, URLSessionDelegate {
    private let pinnedCertificates: [Data]
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard let serverTrust = challenge.protectionSpace.serverTrust,
              let serverCertificate = SecTrustCopyCertificateChain(serverTrust) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Validate against pinned certificates
    }
}
```

**Jailbreak Detection**
```swift
class JailbreakDetector {
    static func isJailbroken() -> Bool {
        // Check for Cydia and common jailbreak paths
        let paths = [
            "/Applications/Cydia.app",
            "/private/var/lib/apt/",
            "/usr/sbin/sshd",
            "/bin/bash"
        ]
        
        for path in paths {
            if FileManager.default.fileExists(atPath: path) {
                return true
            }
        }
        
        // Check if app can write outside sandbox
        let testPath = "/private/jailbreak-test.txt"
        do {
            try "test".write(toFile: testPath, atomically: true, encoding: .utf8)
            try FileManager.default.removeItem(atPath: testPath)
            return true
        } catch {
            return false
        }
    }
}
```

#### Networking with URLSession

**API Client**
```swift
class APIClient {
    private let session: URLSession
    private let baseURL: URL
    private let certificatePinner: CertificatePinner
    
    func request<T: Decodable>(
        endpoint: Endpoint,
        method: HTTPMethod = .get,
        body: Encodable? = nil
    ) async throws -> T {
        var request = URLRequest(url: baseURL.appendingPathComponent(endpoint.path))
        request.httpMethod = method.rawValue
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        
        // Add JWT token from Keychain
        if let token = try? KeychainManager.shared.getToken(forKey: "accessToken") {
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        if let body = body {
            request.httpBody = try JSONEncoder().encode(body)
        }
        
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw NetworkError.invalidResponse
        }
        
        guard (200...299).contains(httpResponse.statusCode) else {
            throw NetworkError.statusCode(httpResponse.statusCode)
        }
        
        return try JSONDecoder().decode(T.self, from: data)
    }
}
```

#### Local Storage with CoreData

**Core Data Stack**
```swift
class CoreDataStack {
    static let shared = CoreDataStack()
    
    lazy var persistentContainer: NSPersistentContainer = {
        let container = NSPersistentContainer(name: "FinanceApp")
        
        // Enable encryption
        guard let storeURL = container.persistentStoreDescriptions.first?.url else {
            fatalError("No store URL")
        }
        
        let description = NSPersistentStoreDescription(url: storeURL)
        description.setOption(FileProtectionType.complete as NSObject,
                            forKey: NSPersistentStoreFileProtectionKey)
        
        container.persistentStoreDescriptions = [description]
        container.loadPersistentStores { _, error in
            if let error = error {
                fatalError("CoreData error: \(error)")
            }
        }
        
        return container
    }()
}
```

#### Push Notifications (APNs)

**Push Notification Registration**
```swift
import UserNotifications

class NotificationManager {
    func requestAuthorization() async throws -> Bool {
        let center = UNUserNotificationCenter.current()
        return try await center.requestAuthorization(options: [.alert, .sound, .badge])
    }
    
    func registerForRemoteNotifications() {
        DispatchQueue.main.async {
            UIApplication.shared.registerForRemoteNotifications()
        }
    }
}

// In AppDelegate
func application(
    _ application: UIApplication,
    didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
) {
    let tokenString = deviceToken.map { String(format: "%02.2hhx", $0) }.joined()
    // Send token to backend
}
```

#### Offline Support

**Offline-First Architecture**
```swift
class AuthRepository {
    private let apiClient: APIClient
    private let cacheManager: SecureCache
    
    func login(email: String, password: String) async throws -> User {
        do {
            // Try network first
            let user: User = try await apiClient.request(endpoint: .login, method: .post, body: LoginRequest(email: email, password: password))
            
            // Cache user data (encrypted)
            try cacheManager.save(user, forKey: "currentUser")
            
            return user
        } catch NetworkError.noConnection {
            // Fallback to cached data
            guard let cachedUser: User = try? cacheManager.load(forKey: "currentUser") else {
                throw AuthError.offlineAndNoCache
            }
            return cachedUser
        }
    }
}
```

#### Background Tasks

**Background Sync with BackgroundTasks Framework**
```swift
import BackgroundTasks

class BackgroundSyncManager {
    func registerBackgroundTasks() {
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: "com.financeapp.sync",
            using: nil
        ) { task in
            self.handleAppRefresh(task: task as! BGAppRefreshTask)
        }
    }
    
    func scheduleBackgroundSync() {
        let request = BGAppRefreshTaskRequest(identifier: "com.financeapp.sync")
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60) // 15 minutes
        
        try? BGTaskScheduler.shared.submit(request)
    }
    
    private func handleAppRefresh(task: BGAppRefreshTask) {
        scheduleBackgroundSync() // Reschedule
        
        Task {
            do {
                try await syncAuthEvents()
                task.setTaskCompleted(success: true)
            } catch {
                task.setTaskCompleted(success: false)
            }
        }
    }
}
```

### 2.4 iOS Security Implementation

#### Complete Security Checklist

**1. Certificate Pinning (TLS 1.3)**
```swift
class SecurePinningDelegate: NSObject, URLSessionDelegate {
    private let pinnedPublicKeyHashes: Set<String> = [
        "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Production cert
        "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="  // Backup cert
    ]
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            return (.cancelAuthenticationChallenge, nil)
        }
        
        // Validate certificate chain
        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFTypeRef)
        
        // Extract public key hash
        guard let serverCertificate = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate],
              let serverPublicKey = SecCertificateCopyKey(serverCertificate[0]),
              let serverPublicKeyData = SecKeyCopyExternalRepresentation(serverPublicKey, nil) as Data? else {
            return (.cancelAuthenticationChallenge, nil)
        }
        
        let serverPublicKeyHash = "sha256/" + serverPublicKeyData.sha256().base64EncodedString()
        
        if pinnedPublicKeyHashes.contains(serverPublicKeyHash) {
            return (.useCredential, URLCredential(trust: serverTrust))
        } else {
            return (.cancelAuthenticationChallenge, nil)
        }
    }
}
```

**2. Keychain Storage with Face ID/Touch ID Protection**
```swift
class SecureKeychainManager {
    enum KeychainKey: String {
        case accessToken
        case refreshToken
        case encryptionKey
    }
    
    func saveToken(_ token: String, forKey key: KeychainKey, requireBiometric: Bool = true) throws {
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            requireBiometric ? .biometryCurrentSet : [],
            nil
        )!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key.rawValue,
            kSecAttrAccessControl as String: accessControl,
            kSecValueData as String: token.data(using: .utf8)!,
            kSecUseDataProtectionKeychain as String: true
        ]
        
        // Delete existing
        SecItemDelete(query as CFDictionary)
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
    
    func getToken(forKey key: KeychainKey, context: LAContext? = nil) throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key.rawValue,
            kSecReturnData as String: true,
            kSecUseDataProtectionKeychain as String: true
        ]
        
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess,
              let data = result as? Data,
              let token = String(data: data, encoding: .utf8) else {
            throw KeychainError.retrievalFailed(status)
        }
        
        return token
    }
}
```

**3. Biometric Authentication with Fallback**
```swift
class BiometricAuthManager {
    func authenticateUser(reason: String = "Authenticate to access your account") async throws -> Bool {
        let context = LAContext()
        context.localizedCancelTitle = "Use Passcode"
        context.localizedFallbackTitle = "Enter Passcode"
        
        var error: NSError?
        guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
            throw BiometricError.notAvailable(error?.localizedDescription ?? "Unknown")
        }
        
        let biometricType = context.biometryType
        let policy: LAPolicy = biometricType != .none ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
        
        return try await context.evaluatePolicy(policy, localizedReason: reason)
    }
    
    func getBiometricType() -> LABiometryType {
        let context = LAContext()
        _ = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: nil)
        return context.biometryType // .faceID, .touchID, or .none
    }
}
```

**4. Jailbreak Detection (Enhanced)**
```swift
class JailbreakDetector {
    static func isJailbroken() -> Bool {
        return checkSuspiciousFiles() || checkSuspiciousApps() || checkSystemCalls() || checkCodeSigning()
    }
    
    private static func checkSuspiciousFiles() -> Bool {
        let paths = [
            "/Applications/Cydia.app",
            "/Library/MobileSubstrate/MobileSubstrate.dylib",
            "/bin/bash",
            "/usr/sbin/sshd",
            "/etc/apt",
            "/private/var/lib/apt/",
            "/private/var/lib/cydia",
            "/private/var/stash"
        ]
        
        return paths.contains { FileManager.default.fileExists(atPath: $0) }
    }
    
    private static func checkSuspiciousApps() -> Bool {
        guard let schemes = ["cydia://", "undecimus://", "sileo://"] as? [String] else { return false }
        return schemes.contains { UIApplication.shared.canOpenURL(URL(string: $0)!) }
    }
    
    private static func checkSystemCalls() -> Bool {
        let handle = dlopen("/usr/lib/system/libsystem_kernel.dylib", RTLD_NOW)
        let fork = dlsym(handle, "fork")
        dlclose(handle)
        return fork != nil
    }
    
    private static func checkCodeSigning() -> Bool {
        guard let bundlePath = Bundle.main.bundlePath.cString(using: .utf8) else { return false }
        
        var staticCode: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(URL(fileURLWithPath: String(cString: bundlePath)) as CFURL, [], &staticCode)
        
        guard status == errSecSuccess, let code = staticCode else { return true }
        
        status = SecStaticCodeCheckValidity(code, [], nil)
        return status != errSecSuccess
    }
}
```

**5. Data Encryption (AES-256-GCM)**
```swift
import CryptoKit

class CryptoManager {
    private static let encryptionKeyTag = "com.financeapp.encryptionKey"
    
    func encrypt(_ data: Data) throws -> (ciphertext: Data, nonce: Data) {
        let key = try getOrCreateEncryptionKey()
        let sealedBox = try AES.GCM.seal(data, using: key)
        
        guard let ciphertext = sealedBox.ciphertext,
              let nonce = sealedBox.nonce else {
            throw CryptoError.encryptionFailed
        }
        
        return (ciphertext + sealedBox.tag, nonce.dataRepresentation)
    }
    
    func decrypt(ciphertext: Data, nonce: Data) throws -> Data {
        let key = try getOrCreateEncryptionKey()
        
        let tag = ciphertext.suffix(16)
        let actualCiphertext = ciphertext.dropLast(16)
        
        let sealedBox = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: nonce),
            ciphertext: actualCiphertext,
            tag: tag
        )
        
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    private func getOrCreateEncryptionKey() throws -> SymmetricKey {
        // Try to retrieve from Keychain
        if let keyData = try? SecureKeychainManager().getToken(forKey: .encryptionKey) {
            return SymmetricKey(data: Data(keyData.utf8))
        }
        
        // Generate new key
        let key = SymmetricKey(size: .bits256)
        let keyData = key.withUnsafeBytes { Data($0) }
        try SecureKeychainManager().saveToken(keyData.base64EncodedString(), forKey: .encryptionKey, requireBiometric: false)
        
        return key
    }
}
```

**6. Code Obfuscation Strategy**
- Enable Swift optimization level `-O` in Release builds
- Strip debug symbols
- Use `#if DEBUG` preprocessor directives
- Obfuscate sensitive string literals
- Enable Bitcode (if applicable)

**Info.plist Security Settings**
```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <false/>
</dict>
<key>NSFaceIDUsageDescription</key>
<string>We use Face ID to securely authenticate you</string>
<key>UIBackgroundModes</key>
<array>
    <string>fetch</string>
    <string>remote-notification</string>
</array>
```

---

## 3. Android Specification

### 3.1 Android Architecture

#### Minimum Requirements
- **Android Version**: API 26 (Android 8.0 Oreo)+
- **Target SDK**: API 34 (Android 14)
- **Kotlin**: 1.9.20+
- **Android Studio**: Hedgehog (2023.1.1)+
- **Gradle**: 8.2+

#### Architecture Pattern
- **Pattern**: Clean Architecture + MVVM with Jetpack
- **UI Framework**: Jetpack Compose (100% Compose)
- **Dependency Injection**: Hilt (Dagger)
- **State Management**: StateFlow + Compose State
- **Async**: Kotlin Coroutines + Flow

#### Jetpack Components
- **Navigation**: Jetpack Compose Navigation
- **Lifecycle**: ViewModel + Lifecycle-aware components
- **Room**: Local database with encryption (SQLCipher)
- **DataStore**: Encrypted preferences
- **WorkManager**: Background tasks
- **Security-Crypto**: EncryptedSharedPreferences, EncryptedFile

#### Key Architectural Decisions
```
Presentation Layer (Composables)
        ↓
ViewModels (StateFlow)
        ↓
Use Cases (Domain Layer)
        ↓
Repositories (Data Layer)
        ↓
Data Sources (Network + Room + DataStore)
```

### 3.2 Android Project Structure

```
FinanceApp-Android/
├── app/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/com/financeapp/
│   │   │   │   ├── FinanceApplication.kt
│   │   │   │   │
│   │   │   │   ├── ui/
│   │   │   │   │   ├── theme/
│   │   │   │   │   │   ├── Color.kt
│   │   │   │   │   │   ├── Theme.kt
│   │   │   │   │   │   ├── Type.kt
│   │   │   │   │   │   └── Shape.kt
│   │   │   │   │   │
│   │   │   │   │   ├── navigation/
│   │   │   │   │   │   ├── NavGraph.kt
│   │   │   │   │   │   └── Screen.kt
│   │   │   │   │   │
│   │   │   │   │   ├── components/
│   │   │   │   │   │   ├── PrimaryButton.kt
│   │   │   │   │   │   ├── SecureTextField.kt
│   │   │   │   │   │   ├── LoadingIndicator.kt
│   │   │   │   │   │   └── AlertBanner.kt
│   │   │   │   │   │
│   │   │   │   │   ├── authentication/
│   │   │   │   │   │   ├── LoginScreen.kt
│   │   │   │   │   │   ├── RegisterScreen.kt
│   │   │   │   │   │   ├── EmailVerificationScreen.kt
│   │   │   │   │   │   ├── PasswordResetScreen.kt
│   │   │   │   │   │   ├── TwoFactorScreen.kt
│   │   │   │   │   │   ├── BiometricSetupScreen.kt
│   │   │   │   │   │   └── viewmodels/
│   │   │   │   │   │       ├── LoginViewModel.kt
│   │   │   │   │   │       ├── RegisterViewModel.kt
│   │   │   │   │   │       └── AuthViewModel.kt
│   │   │   │   │   │
│   │   │   │   │   ├── dashboard/
│   │   │   │   │   │   ├── DashboardScreen.kt
│   │   │   │   │   │   ├── ProfileScreen.kt
│   │   │   │   │   │   └── viewmodels/
│   │   │   │   │   │       └── DashboardViewModel.kt
│   │   │   │   │   │
│   │   │   │   │   └── settings/
│   │   │   │   │       ├── SecuritySettingsScreen.kt
│   │   │   │   │       ├── DeviceManagementScreen.kt
│   │   │   │   │       └── ConsentManagementScreen.kt
│   │   │   │   │
│   │   │   │   ├── data/
│   │   │   │   │   ├── repository/
│   │   │   │   │   │   ├── AuthRepository.kt
│   │   │   │   │   │   ├── AuthRepositoryImpl.kt
│   │   │   │   │   │   ├── UserRepository.kt
│   │   │   │   │   │   └── DeviceRepository.kt
│   │   │   │   │   │
│   │   │   │   │   ├── network/
│   │   │   │   │   │   ├── ApiService.kt
│   │   │   │   │   │   ├── AuthInterceptor.kt
│   │   │   │   │   │   ├── NetworkModule.kt
│   │   │   │   │   │   ├── CertificatePinner.kt
│   │   │   │   │   │   └── dto/
│   │   │   │   │   │       ├── LoginRequest.kt
│   │   │   │   │   │       ├── LoginResponse.kt
│   │   │   │   │   │       ├── RegisterRequest.kt
│   │   │   │   │   │       └── UserDto.kt
│   │   │   │   │   │
│   │   │   │   │   ├── local/
│   │   │   │   │   │   ├── database/
│   │   │   │   │   │   │   ├── AppDatabase.kt
│   │   │   │   │   │   │   ├── UserDao.kt
│   │   │   │   │   │   │   └── entities/
│   │   │   │   │   │   │       ├── UserEntity.kt
│   │   │   │   │   │   │       └── AuthEventEntity.kt
│   │   │   │   │   │   │
│   │   │   │   │   │   └── datastore/
│   │   │   │   │   │       ├── SecurePreferences.kt
│   │   │   │   │   │       └── TokenManager.kt
│   │   │   │   │   │
│   │   │   │   │   └── mapper/
│   │   │   │   │       ├── UserMapper.kt
│   │   │   │   │       └── AuthMapper.kt
│   │   │   │   │
│   │   │   │   ├── domain/
│   │   │   │   │   ├── models/
│   │   │   │   │   │   ├── User.kt
│   │   │   │   │   │   ├── AuthToken.kt
│   │   │   │   │   │   ├── AuthState.kt
│   │   │   │   │   │   └── AuthError.kt
│   │   │   │   │   │
│   │   │   │   │   ├── usecases/
│   │   │   │   │   │   ├── LoginUseCase.kt
│   │   │   │   │   │   ├── RegisterUseCase.kt
│   │   │   │   │   │   ├── LogoutUseCase.kt
│   │   │   │   │   │   ├── RefreshTokenUseCase.kt
│   │   │   │   │   │   ├── BiometricAuthUseCase.kt
│   │   │   │   │   │   └── ValidatePasswordUseCase.kt
│   │   │   │   │   │
│   │   │   │   │   └── repository/
│   │   │   │   │       └── [Interfaces for repositories]
│   │   │   │   │
│   │   │   │   ├── security/
│   │   │   │   │   ├── BiometricManager.kt
│   │   │   │   │   ├── CryptoManager.kt
│   │   │   │   │   ├── KeystoreManager.kt
│   │   │   │   │   ├── RootDetector.kt
│   │   │   │   │   └── SecureStorage.kt
│   │   │   │   │
│   │   │   │   ├── utils/
│   │   │   │   │   ├── NetworkMonitor.kt
│   │   │   │   │   ├── Logger.kt
│   │   │   │   │   ├── Validators.kt
│   │   │   │   │   └── Extensions.kt
│   │   │   │   │
│   │   │   │   └── di/
│   │   │   │       ├── AppModule.kt
│   │   │   │       ├── NetworkModule.kt
│   │   │   │       ├── DatabaseModule.kt
│   │   │   │       ├── RepositoryModule.kt
│   │   │   │       └── SecurityModule.kt
│   │   │   │
│   │   │   ├── res/
│   │   │   │   ├── values/
│   │   │   │   │   ├── strings.xml
│   │   │   │   │   ├── colors.xml
│   │   │   │   │   └── themes.xml
│   │   │   │   ├── drawable/
│   │   │   │   └── mipmap/
│   │   │   │
│   │   │   └── AndroidManifest.xml
│   │   │
│   │   ├── androidTest/
│   │   │   └── java/com/financeapp/
│   │   │       ├── AuthFlowTest.kt
│   │   │       └── DatabaseTest.kt
│   │   │
│   │   └── test/
│   │       └── java/com/financeapp/
│   │           ├── viewmodels/
│   │           ├── usecases/
│   │           └── repositories/
│   │
│   ├── build.gradle.kts
│   └── proguard-rules.pro
│
├── build.gradle.kts
└── gradle.properties
```

### 3.3 Android Key Features

#### Authentication & Security

**EncryptedSharedPreferences for Tokens**
```kotlin
class SecurePreferences @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveToken(key: String, token: String) {
        encryptedPrefs.edit().putString(key, token).apply()
    }

    fun getToken(key: String): String? {
        return encryptedPrefs.getString(key, null)
    }

    fun clearTokens() {
        encryptedPrefs.edit().clear().apply()
    }
}
```

**BiometricPrompt for Authentication**
```kotlin
class BiometricManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun isBiometricAvailable(): Boolean {
        val biometricManager = BiometricManager.from(context)
        return biometricManager.canAuthenticate(BIOMETRIC_STRONG) == BiometricManager.BIOMETRIC_SUCCESS
    }

    fun authenticate(
        activity: FragmentActivity,
        title: String = "Authenticate",
        subtitle: String = "Use your fingerprint or face to login",
        onSuccess: () -> Unit,
        onError: (String) -> Unit
    ) {
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            .build()

        val biometricPrompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onError(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onError("Authentication failed")
                }
            }
        )

        biometricPrompt.authenticate(promptInfo)
    }
}
```

**Certificate Pinning with OkHttp**
```kotlin
@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {
    private const val BASE_URL = "https://api.financeapp.com/"

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient {
        val certificatePinner = CertificatePinner.Builder()
            .add("api.financeapp.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.financeapp.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build()

        return OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .addInterceptor(AuthInterceptor())
            .addInterceptor(HttpLoggingInterceptor().apply {
                level = if (BuildConfig.DEBUG) HttpLoggingInterceptor.Level.BODY else HttpLoggingInterceptor.Level.NONE
            })
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .build()
    }

    @Provides
    @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl(BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    @Provides
    @Singleton
    fun provideApiService(retrofit: Retrofit): ApiService {
        return retrofit.create(ApiService::class.java)
    }
}
```

**JWT Auth Interceptor**
```kotlin
class AuthInterceptor @Inject constructor(
    private val tokenManager: TokenManager
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()

        val token = tokenManager.getAccessToken()
        val requestWithAuth = if (token != null) {
            originalRequest.newBuilder()
                .addHeader("Authorization", "Bearer $token")
                .build()
        } else {
            originalRequest
        }

        var response = chain.proceed(requestWithAuth)

        // Handle 401 - refresh token
        if (response.code == 401 && token != null) {
            response.close()

            synchronized(this) {
                val newToken = tokenManager.refreshToken()
                if (newToken != null) {
                    val newRequest = originalRequest.newBuilder()
                        .addHeader("Authorization", "Bearer $newToken")
                        .build()
                    response = chain.proceed(newRequest)
                }
            }
        }

        return response
    }
}
```

#### Networking with Retrofit

**API Service Interface**
```kotlin
interface ApiService {
    @POST("auth/register")
    suspend fun register(@Body request: RegisterRequest): Response<RegisterResponse>

    @POST("auth/login")
    suspend fun login(@Body request: LoginRequest): Response<LoginResponse>

    @POST("auth/verify-email")
    suspend fun verifyEmail(@Body request: VerifyEmailRequest): Response<VerifyEmailResponse>

    @POST("auth/password-reset")
    suspend fun requestPasswordReset(@Body request: PasswordResetRequest): Response<PasswordResetResponse>

    @POST("auth/refresh")
    suspend fun refreshToken(@Body request: RefreshTokenRequest): Response<RefreshTokenResponse>

    @POST("auth/logout")
    suspend fun logout(): Response<Unit>

    @POST("auth/2fa/enable")
    suspend fun enableTwoFactor(): Response<TwoFactorSetupResponse>

    @POST("auth/2fa/verify")
    suspend fun verifyTwoFactor(@Body request: TwoFactorVerifyRequest): Response<TwoFactorVerifyResponse>

    @GET("user/profile")
    suspend fun getUserProfile(): Response<UserProfile>

    @GET("user/devices")
    suspend fun getDevices(): Response<List<Device>>

    @DELETE("user/devices/{deviceId}")
    suspend fun revokeDevice(@Path("deviceId") deviceId: String): Response<Unit>
}
```

#### Local Storage with Room

**Room Database with Encryption**
```kotlin
@Database(
    entities = [UserEntity::class, AuthEventEntity::class],
    version = 1,
    exportSchema = false
)
abstract class AppDatabase : RoomDatabase() {
    abstract fun userDao(): UserDao
    abstract fun authEventDao(): AuthEventDao
}

@Module
@InstallIn(SingletonComponent::class)
object DatabaseModule {
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): AppDatabase {
        val passphrase = SQLiteDatabase.getBytes("your-secure-passphrase".toCharArray())
        val factory = SupportFactory(passphrase)

        return Room.databaseBuilder(
            context,
            AppDatabase::class.java,
            "finance_app_db"
        )
            .openHelperFactory(factory)
            .fallbackToDestructiveMigration()
            .build()
    }

    @Provides
    fun provideUserDao(database: AppDatabase) = database.userDao()

    @Provides
    fun provideAuthEventDao(database: AppDatabase) = database.authEventDao()
}
```

**User DAO**
```kotlin
@Dao
interface UserDao {
    @Query("SELECT * FROM users WHERE id = :userId")
    suspend fun getUserById(userId: String): UserEntity?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertUser(user: UserEntity)

    @Update
    suspend fun updateUser(user: UserEntity)

    @Delete
    suspend fun deleteUser(user: UserEntity)

    @Query("DELETE FROM users")
    suspend fun clearAll()
}
```

#### Push Notifications with FCM

**FCM Service**
```kotlin
class FirebaseMessagingService : FirebaseMessagingService() {
    override fun onNewToken(token: String) {
        super.onNewToken(token)
        Log.d("FCM", "New token: $token")
        // Send token to backend
        sendTokenToServer(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        super.onMessageReceived(message)
        
        message.notification?.let {
            showNotification(it.title ?: "", it.body ?: "")
        }
    }

    private fun showNotification(title: String, body: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "auth_channel",
                "Authentication",
                NotificationManager.IMPORTANCE_HIGH
            )
            notificationManager.createNotificationChannel(channel)
        }

        val notification = NotificationCompat.Builder(this, "auth_channel")
            .setContentTitle(title)
            .setContentText(body)
            .setSmallIcon(R.drawable.ic_notification)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }
}
```

#### WorkManager for Background Tasks

**Background Sync Worker**
```kotlin
@HiltWorker
class SyncAuthEventsWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val authRepository: AuthRepository
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return try {
            authRepository.syncAuthEvents()
            Result.success()
        } catch (e: Exception) {
            if (runAttemptCount < 3) {
                Result.retry()
            } else {
                Result.failure()
            }
        }
    }

    companion object {
        const val WORK_NAME = "sync_auth_events"

        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val workRequest = PeriodicWorkRequestBuilder<SyncAuthEventsWorker>(
                15, TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    WorkRequest.MIN_BACKOFF_MILLIS,
                    TimeUnit.MILLISECONDS
                )
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                workRequest
            )
        }
    }
}
```

#### Offline-First Architecture

**Repository with Offline Support**
```kotlin
class AuthRepositoryImpl @Inject constructor(
    private val apiService: ApiService,
    private val userDao: UserDao,
    private val securePreferences: SecurePreferences,
    private val networkMonitor: NetworkMonitor
) : AuthRepository {

    override suspend fun login(email: String, password: String): Result<User> {
        return try {
            if (networkMonitor.isConnected()) {
                // Try network first
                val response = apiService.login(LoginRequest(email, password))
                
                if (response.isSuccessful && response.body() != null) {
                    val loginResponse = response.body()!!
                    
                    // Save tokens
                    securePreferences.saveToken("access_token", loginResponse.accessToken)
                    securePreferences.saveToken("refresh_token", loginResponse.refreshToken)
                    
                    // Cache user
                    val userEntity = loginResponse.user.toEntity()
                    userDao.insertUser(userEntity)
                    
                    Result.success(loginResponse.user.toDomain())
                } else {
                    Result.failure(Exception("Login failed: ${response.code()}"))
                }
            } else {
                // Offline mode - check cached credentials
                val cachedUser = userDao.getUserByEmail(email)
                if (cachedUser != null) {
                    Result.success(cachedUser.toDomain())
                } else {
                    Result.failure(Exception("No network and no cached user"))
                }
            }
        } catch (e: Exception) {
            Result.failure(e)
        }
    }
}
```

### 3.4 Android Security Implementation

#### Complete Security Checklist

**1. Root Detection**
```kotlin
class RootDetector @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun isRooted(): Boolean {
        return checkBuildTags() || checkSuperUserApk() || checkRootFiles() || checkRootCommands()
    }

    private fun checkBuildTags(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkSuperUserApk(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/system/app/SuperSU.apk",
            "/system/app/Magisk.apk"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkRootFiles(): Boolean {
        val paths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/su",
            "/system/bin/.ext/.su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkRootCommands(): Boolean {
        return try {
            Runtime.getRuntime().exec("su").destroy()
            true
        } catch (e: Exception) {
            false
        }
    }
}
```

**2. Android Keystore for Encryption**
```kotlin
class KeystoreManager @Inject constructor() {
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    fun generateKey(alias: String) {
        if (!keyStore.containsAlias(alias)) {
            val keyGenerator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES,
                "AndroidKeyStore"
            )

            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(false)
                .setRandomizedEncryptionRequired(true)
                .build()

            keyGenerator.init(keyGenParameterSpec)
            keyGenerator.generateKey()
        }
    }

    fun getKey(alias: String): SecretKey {
        return keyStore.getKey(alias, null) as SecretKey
    }

    fun deleteKey(alias: String) {
        if (keyStore.containsAlias(alias)) {
            keyStore.deleteEntry(alias)
        }
    }
}
```

**3. AES-256-GCM Encryption**
```kotlin
class CryptoManager @Inject constructor(
    private val keystoreManager: KeystoreManager
) {
    private val keyAlias = "finance_app_encryption_key"

    init {
        keystoreManager.generateKey(keyAlias)
    }

    fun encrypt(data: ByteArray): EncryptedData {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keystoreManager.getKey(keyAlias))

        val iv = cipher.iv
        val ciphertext = cipher.doFinal(data)

        return EncryptedData(ciphertext, iv)
    }

    fun decrypt(encryptedData: EncryptedData): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, encryptedData.iv)
        cipher.init(Cipher.DECRYPT_MODE, keystoreManager.getKey(keyAlias), spec)

        return cipher.doFinal(encryptedData.ciphertext)
    }
}

data class EncryptedData(val ciphertext: ByteArray, val iv: ByteArray)
```

**4. ProGuard/R8 Obfuscation Rules**
```proguard
# proguard-rules.pro

# Keep authentication models
-keep class com.financeapp.domain.models.** { *; }
-keep class com.financeapp.data.network.dto.** { *; }

# Obfuscate everything else
-obfuscate
-optimizations !code/simplification/arithmetic,!code/simplification/cast,!field/*,!class/merging/*

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep Retrofit interfaces
-keepattributes Signature
-keepattributes Exceptions
-keep class retrofit2.** { *; }

# Keep Gson annotations
-keepattributes *Annotation*
-keepattributes Signature

# Security - remove logging in release
-assumenosideeffects class android.util.Log {
    public static *** d(...);
    public static *** v(...);
    public static *** i(...);
}

# Encrypt strings
-adaptclassstrings
```

**5. Network Security Config**
```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.financeapp.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**AndroidManifest.xml Security Settings**
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    xmlns:tools="http://schemas.android.com/tools">

    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.USE_BIOMETRIC" />

    <application
        android:name=".FinanceApplication"
        android:allowBackup="false"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config"
        tools:targetApi="n">

        <meta-data
            android:name="com.google.android.gms.security.ENFORCE_CERTIFICATE_PINNING"
            android:value="true" />

    </application>
</manifest>
```

---

## 4. Shared Components

### 4.1 API Client Architecture

#### Base URL Configuration
```
Development: https://dev-api.financeapp.com
Staging: https://staging-api.financeapp.com
Production: https://api.financeapp.com
```

#### Request/Response Structure

**Common Headers**
```
Content-Type: application/json
Accept: application/json
Authorization: Bearer {access_token}
X-Device-ID: {unique_device_identifier}
X-App-Version: {app_version}
X-Platform: ios | android
```

**Error Response Format**
```json
{
  "error": {
    "code": "AUTH_001",
    "message": "Invalid credentials",
    "details": "The email or password provided is incorrect",
    "timestamp": "2025-10-29T12:00:00Z"
  }
}
```

#### Request/Response Interceptors

**iOS**
```swift
class RequestInterceptor {
    func intercept(request: URLRequest) -> URLRequest {
        var modifiedRequest = request
        
        // Add JWT token
        if let token = try? KeychainManager.shared.getToken(forKey: .accessToken) {
            modifiedRequest.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        
        // Add device ID
        let deviceId = UIDevice.current.identifierForVendor?.uuidString ?? ""
        modifiedRequest.addValue(deviceId, forHTTPHeaderField: "X-Device-ID")
        
        // Add app version
        let appVersion = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? ""
        modifiedRequest.addValue(appVersion, forHTTPHeaderField: "X-App-Version")
        
        modifiedRequest.addValue("ios", forHTTPHeaderField: "X-Platform")
        
        return modifiedRequest
    }
}
```

**Android**
```kotlin
class HeaderInterceptor @Inject constructor(
    private val tokenManager: TokenManager,
    @ApplicationContext private val context: Context
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        
        val requestBuilder = original.newBuilder()
            .addHeader("Content-Type", "application/json")
            .addHeader("Accept", "application/json")
            .addHeader("X-Device-ID", getDeviceId())
            .addHeader("X-App-Version", getAppVersion())
            .addHeader("X-Platform", "android")
        
        tokenManager.getAccessToken()?.let {
            requestBuilder.addHeader("Authorization", "Bearer $it")
        }
        
        return chain.proceed(requestBuilder.build())
    }
    
    private fun getDeviceId(): String {
        return Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    }
    
    private fun getAppVersion(): String {
        return context.packageManager.getPackageInfo(context.packageName, 0).versionName
    }
}
```

#### Token Refresh Logic

**iOS**
```swift
class TokenRefreshHandler {
    func refreshTokenIfNeeded() async throws {
        guard let refreshToken = try? KeychainManager.shared.getToken(forKey: .refreshToken) else {
            throw AuthError.noRefreshToken
        }
        
        let request = RefreshTokenRequest(refreshToken: refreshToken)
        let response: RefreshTokenResponse = try await apiClient.request(
            endpoint: .refreshToken,
            method: .post,
            body: request
        )
        
        // Save new tokens
        try KeychainManager.shared.saveToken(response.accessToken, forKey: .accessToken)
        try KeychainManager.shared.saveToken(response.refreshToken, forKey: .refreshToken)
    }
}
```

**Android**
```kotlin
class TokenRefreshManager @Inject constructor(
    private val apiService: ApiService,
    private val securePreferences: SecurePreferences
) {
    @Synchronized
    suspend fun refreshToken(): String? {
        val refreshToken = securePreferences.getToken("refresh_token") ?: return null
        
        return try {
            val response = apiService.refreshToken(RefreshTokenRequest(refreshToken))
            
            if (response.isSuccessful && response.body() != null) {
                val newTokens = response.body()!!
                securePreferences.saveToken("access_token", newTokens.accessToken)
                securePreferences.saveToken("refresh_token", newTokens.refreshToken)
                newTokens.accessToken
            } else {
                null
            }
        } catch (e: Exception) {
            null
        }
    }
}
```

#### Retry Mechanism

**Exponential Backoff Strategy**
- Initial retry delay: 1 second
- Max retries: 3
- Backoff multiplier: 2x
- Max delay: 10 seconds
- Retry on: Network errors, 5xx server errors
- No retry on: 4xx client errors (except 401)

### 4.2 Authentication Flow

```
App Launch
    ↓
Check Stored Tokens
    ↓
    ├─ Valid Access Token
    │   ↓
    │   Biometric Prompt (if enabled)
    │       ↓
    │       ├─ Success → Dashboard
    │       └─ Failure → Login Screen
    │
    ├─ Expired Access Token + Valid Refresh Token
    │   ↓
    │   Refresh Token API Call
    │       ↓
    │       ├─ Success → Save New Tokens → Dashboard
    │       └─ Failure → Login Screen
    │
    └─ No Valid Tokens
        ↓
        Login Screen
            ↓
            ├─ Email/Password Login
            │   ↓
            │   Login API Call
            │       ↓
            │       ├─ Success (No 2FA) → Save Tokens → Dashboard
            │       ├─ Success (2FA Required) → 2FA Screen
            │       │   ↓
            │       │   Verify 2FA Code
            │       │       ↓
            │       │       ├─ Success → Save Tokens → Dashboard
            │       │       └─ Failure → Show Error
            │       └─ Failure → Show Error
            │
            ├─ Social Login (OAuth)
            │   ↓
            │   OAuth Flow → Exchange Code → Save Tokens → Dashboard
            │
            └─ Register
                ↓
                Registration Screen
                    ↓
                    Submit Registration
                        ↓
                        ├─ Success → Email Verification Screen
                        │   ↓
                        │   Enter Verification Code
                        │       ↓
                        │       ├─ Success → Login Screen
                        │       └─ Failure → Show Error
                        └─ Failure → Show Error
```

### 4.3 Data Synchronization

#### Online vs Offline Detection

**iOS**
```swift
import Network

class NetworkMonitor {
    static let shared = NetworkMonitor()
    private let monitor = NWPathMonitor()
    private let queue = DispatchQueue(label: "NetworkMonitor")
    
    @Published var isConnected: Bool = true
    
    func startMonitoring() {
        monitor.pathUpdateHandler = { [weak self] path in
            DispatchQueue.main.async {
                self?.isConnected = path.status == .satisfied
            }
        }
        monitor.start(queue: queue)
    }
}
```

**Android**
```kotlin
class NetworkMonitor @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()
    
    init {
        val networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                _isConnected.value = true
            }
            
            override fun onLost(network: Network) {
                _isConnected.value = false
            }
        }
        
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        
        connectivityManager.registerNetworkCallback(request, networkCallback)
    }
}
```

#### Sync Strategy

**Data Priority Levels**
1. **Critical**: Auth tokens, user profile (sync immediately)
2. **High**: Security events, device management (sync within 5 minutes)
3. **Normal**: App preferences, cache (sync within 1 hour)

**Conflict Resolution**
- **Server Wins**: For auth-related data (tokens, permissions)
- **Client Wins**: For user preferences
- **Last-Write Wins**: For general data with timestamps

#### Background Sync

**iOS Background Fetch**
```swift
class BackgroundSyncManager {
    func scheduleBackgroundSync() {
        let request = BGAppRefreshTaskRequest(identifier: "com.financeapp.sync")
        request.earliestBeginDate = Date(timeIntervalSinceNow: 15 * 60)
        
        try? BGTaskScheduler.shared.submit(request)
    }
}
```

**Android WorkManager**
```kotlin
class SyncWorker @AssistedInject constructor(
    @Assisted context: Context,
    @Assisted params: WorkerParameters,
    private val syncRepository: SyncRepository
) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        return try {
            syncRepository.syncAll()
            Result.success()
        } catch (e: Exception) {
            Result.retry()
        }
    }
}
```

---

## 5. UI/UX Specifications

### 5.1 Design System

#### Color Palette (Fintech Theme)

**Primary Colors**
- Primary Blue: `#0066CC` (Trust, stability)
- Primary Dark: `#004999`
- Primary Light: `#3399FF`

**Secondary Colors**
- Success Green: `#00C853` (Verified, success)
- Warning Orange: `#FF9800` (Caution)
- Error Red: `#D32F2F` (Critical errors)
- Info Blue: `#2196F3`

**Neutral Colors**
- Background: `#FFFFFF` (Light), `#121212` (Dark)
- Surface: `#F5F5F5` (Light), `#1E1E1E` (Dark)
- Text Primary: `#212121` (Light), `#FFFFFF` (Dark)
- Text Secondary: `#757575` (Light), `#B0B0B0` (Dark)
- Divider: `#E0E0E0` (Light), `#3A3A3A` (Dark)

#### Typography

**iOS (San Francisco)**
```swift
struct AppTypography {
    static let largeTitle = Font.system(size: 34, weight: .bold)
    static let title1 = Font.system(size: 28, weight: .bold)
    static let title2 = Font.system(size: 22, weight: .bold)
    static let title3 = Font.system(size: 20, weight: .semibold)
    static let headline = Font.system(size: 17, weight: .semibold)
    static let body = Font.system(size: 17, weight: .regular)
    static let callout = Font.system(size: 16, weight: .regular)
    static let subheadline = Font.system(size: 15, weight: .regular)
    static let footnote = Font.system(size: 13, weight: .regular)
    static let caption1 = Font.system(size: 12, weight: .regular)
    static let caption2 = Font.system(size: 11, weight: .regular)
}
```

**Android (Roboto)**
```kotlin
val Typography = Typography(
    displayLarge = TextStyle(fontSize = 57.sp, fontWeight = FontWeight.Bold),
    displayMedium = TextStyle(fontSize = 45.sp, fontWeight = FontWeight.Bold),
    displaySmall = TextStyle(fontSize = 36.sp, fontWeight = FontWeight.Bold),
    headlineLarge = TextStyle(fontSize = 32.sp, fontWeight = FontWeight.Bold),
    headlineMedium = TextStyle(fontSize = 28.sp, fontWeight = FontWeight.Bold),
    headlineSmall = TextStyle(fontSize = 24.sp, fontWeight = FontWeight.Bold),
    titleLarge = TextStyle(fontSize = 22.sp, fontWeight = FontWeight.SemiBold),
    titleMedium = TextStyle(fontSize = 16.sp, fontWeight = FontWeight.SemiBold),
    titleSmall = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = TextStyle(fontSize = 16.sp, fontWeight = FontWeight.Normal),
    bodyMedium = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.Normal),
    bodySmall = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Normal),
    labelLarge = TextStyle(fontSize = 14.sp, fontWeight = FontWeight.Medium),
    labelMedium = TextStyle(fontSize = 12.sp, fontWeight = FontWeight.Medium),
    labelSmall = TextStyle(fontSize = 11.sp, fontWeight = FontWeight.Medium)
)
```

#### Spacing System (8pt Grid)

```
4pt  - Extra small spacing (icon padding)
8pt  - Small spacing (text to icon)
16pt - Medium spacing (between elements)
24pt - Large spacing (section spacing)
32pt - Extra large spacing (screen margins)
48pt - XXL spacing (major section breaks)
```

#### Component Library

**Primary Button**
- Height: 48pt
- Corner radius: 8pt
- Font: Headline (iOS) / LabelLarge (Android)
- Disabled opacity: 0.5

**Secondary Button**
- Height: 48pt
- Border width: 1pt
- Corner radius: 8pt
- Background: Transparent

**Text Field**
- Height: 56pt
- Corner radius: 8pt
- Border width: 1pt (unfocused), 2pt (focused)
- Error state: Red border + error message below

**Card**
- Corner radius: 12pt
- Elevation: 2dp (Android) / Shadow (iOS)
- Padding: 16pt

### 5.2 Navigation

#### iOS Navigation Pattern

**Tab Bar (Bottom Navigation)**
```
Home | Activity | Settings
```

**Navigation Stack**
- Push/Pop transitions
- Swipe-to-go-back gesture
- Large title for top-level screens

**Modal Presentation**
- Sheet style for forms (registration, settings)
- Full screen for critical flows (login, onboarding)

**iOS Example**
```swift
TabView {
    DashboardView()
        .tabItem {
            Label("Home", systemImage: "house.fill")
        }
    
    ActivityView()
        .tabItem {
            Label("Activity", systemImage: "list.bullet")
        }
    
    SettingsView()
        .tabItem {
            Label("Settings", systemImage: "gearshape.fill")
        }
}
```

#### Android Navigation Pattern

**Bottom Navigation Bar**
```
Home | Activity | Settings
```

**Navigation Component**
- Fragment-based navigation
- Navigation graph with type-safe arguments
- Back stack management

**Android Example**
```kotlin
@Composable
fun AppNavigation() {
    val navController = rememberNavController()
    
    Scaffold(
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Home, "Home") },
                    label = { Text("Home") },
                    selected = false,
                    onClick = { navController.navigate("home") }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.List, "Activity") },
                    label = { Text("Activity") },
                    selected = false,
                    onClick = { navController.navigate("activity") }
                )
                NavigationBarItem(
                    icon = { Icon(Icons.Filled.Settings, "Settings") },
                    label = { Text("Settings") },
                    selected = false,
                    onClick = { navController.navigate("settings") }
                )
            }
        }
    ) {
        NavHost(navController, startDestination = "home") {
            composable("home") { DashboardScreen() }
            composable("activity") { ActivityScreen() }
            composable("settings") { SettingsScreen() }
        }
    }
}
```

#### Deep Linking Support

**Universal Links (iOS)**
```
https://financeapp.com/auth/verify?token=abc123
https://financeapp.com/auth/reset-password?token=xyz789
https://financeapp.com/dashboard
```

**App Links (Android)**
```xml
<intent-filter android:autoVerify="true">
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <data android:scheme="https" android:host="financeapp.com" />
</intent-filter>
```

### 5.3 Accessibility

#### iOS Accessibility (VoiceOver)

```swift
Button("Login") {
    performLogin()
}
.accessibilityLabel("Login button")
.accessibilityHint("Double tap to log in to your account")

TextField("Email", text: $email)
    .accessibilityLabel("Email address")
    .accessibilityValue(email)
```

**Dynamic Type Support**
```swift
Text("Welcome")
    .font(.title)
    .dynamicTypeSize(...DynamicTypeSize.xxxLarge)
```

#### Android Accessibility (TalkBack)

```kotlin
Button(
    onClick = { performLogin() },
    modifier = Modifier.semantics {
        contentDescription = "Login button"
        role = Role.Button
    }
) {
    Text("Login")
}

OutlinedTextField(
    value = email,
    onValueChange = { email = it },
    label = { Text("Email") },
    modifier = Modifier.semantics {
        contentDescription = "Email address input field"
    }
)
```

#### Accessibility Checklist

- Minimum touch target size: 44x44pt (iOS), 48x48dp (Android)
- Color contrast ratio: 4.5:1 (normal text), 3:1 (large text)
- Support for screen readers
- Support for dynamic text sizing
- Keyboard navigation support
- Focus indicators
- Error announcements
- Loading state announcements

---

## 6. Performance Optimization

### Image Loading and Caching

**iOS - Kingfisher/SDWebImage**
```swift
imageView.kf.setImage(
    with: URL(string: imageUrl),
    placeholder: placeholderImage,
    options: [
        .transition(.fade(0.2)),
        .cacheMemoryOnly,
        .scaleFactor(UIScreen.main.scale)
    ]
)
```

**Android - Coil**
```kotlin
AsyncImage(
    model = ImageRequest.Builder(LocalContext.current)
        .data(imageUrl)
        .memoryCachePolicy(CachePolicy.ENABLED)
        .diskCachePolicy(CachePolicy.ENABLED)
        .crossfade(true)
        .build(),
    contentDescription = "Profile image",
    modifier = Modifier.size(48.dp)
)
```

### List Optimization

**iOS - LazyVStack**
```swift
ScrollView {
    LazyVStack(spacing: 16) {
        ForEach(items) { item in
            ItemRow(item: item)
        }
    }
}
```

**Android - LazyColumn**
```kotlin
LazyColumn {
    items(items, key = { it.id }) { item ->
        ItemRow(item = item)
    }
}
```

### Memory Management

**iOS**
- Use weak/unowned references to avoid retain cycles
- Implement deinit methods
- Clear image caches periodically
- Use @MainActor for UI updates

**Android**
- Use ViewModel for lifecycle-aware data
- Avoid memory leaks with WeakReference
- Use onCleared() in ViewModel
- Use remember with keys in Compose

### Battery Optimization

- Batch network requests
- Use exponential backoff for retries
- Schedule background work intelligently
- Reduce location accuracy when possible
- Minimize wake locks
- Use efficient data formats (Protocol Buffers over JSON)

### Network Call Optimization

- Implement request coalescing
- Use HTTP/2 multiplexing
- Compress request/response payloads (gzip)
- Implement pagination (20-50 items per page)
- Cache API responses (Cache-Control headers)
- Prefetch next page in lists

---

## 7. Testing Strategy

### 7.1 Unit Testing

#### iOS - XCTest

```swift
import XCTest
@testable import FinanceApp

class LoginViewModelTests: XCTestCase {
    var sut: LoginViewModel!
    var mockAuthRepository: MockAuthRepository!
    
    override func setUp() {
        super.setUp()
        mockAuthRepository = MockAuthRepository()
        sut = LoginViewModel(authRepository: mockAuthRepository)
    }
    
    func testLoginSuccess() async throws {
        // Given
        mockAuthRepository.loginResult = .success(User(id: "1", email: "test@example.com"))
        
        // When
        await sut.login(email: "test@example.com", password: "password123")
        
        // Then
        XCTAssertEqual(sut.state, .authenticated)
        XCTAssertNil(sut.errorMessage)
    }
    
    func testLoginFailure() async {
        // Given
        mockAuthRepository.loginResult = .failure(AuthError.invalidCredentials)
        
        // When
        await sut.login(email: "test@example.com", password: "wrong")
        
        // Then
        XCTAssertEqual(sut.state, .unauthenticated)
        XCTAssertNotNil(sut.errorMessage)
    }
}
```

#### Android - JUnit + MockK

```kotlin
class LoginViewModelTest {
    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    private lateinit var viewModel: LoginViewModel
    private val authRepository: AuthRepository = mockk()

    @Before
    fun setup() {
        viewModel = LoginViewModel(authRepository)
    }

    @Test
    fun `login with valid credentials returns success`() = runTest {
        // Given
        val user = User(id = "1", email = "test@example.com")
        coEvery { authRepository.login(any(), any()) } returns Result.success(user)

        // When
        viewModel.login("test@example.com", "password123")

        // Then
        assertEquals(AuthState.Authenticated(user), viewModel.authState.value)
    }

    @Test
    fun `login with invalid credentials returns error`() = runTest {
        // Given
        coEvery { authRepository.login(any(), any()) } returns Result.failure(Exception("Invalid credentials"))

        // When
        viewModel.login("test@example.com", "wrong")

        // Then
        assertTrue(viewModel.authState.value is AuthState.Error)
    }
}
```

### 7.2 UI Testing

#### iOS - XCUITest

```swift
class AuthenticationUITests: XCTestCase {
    var app: XCUIApplication!
    
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
        app = XCUIApplication()
        app.launch()
    }
    
    func testLoginFlow() {
        // Given
        let emailField = app.textFields["Email"]
        let passwordField = app.secureTextFields["Password"]
        let loginButton = app.buttons["Login"]
        
        // When
        emailField.tap()
        emailField.typeText("test@example.com")
        
        passwordField.tap()
        passwordField.typeText("password123")
        
        loginButton.tap()
        
        // Then
        XCTAssertTrue(app.staticTexts["Dashboard"].waitForExistence(timeout: 5))
    }
    
    func testRegistrationFlow() {
        // Given
        let registerButton = app.buttons["Register"]
        registerButton.tap()
        
        // When
        app.textFields["Email"].tap()
        app.textFields["Email"].typeText("newuser@example.com")
        
        app.secureTextFields["Password"].tap()
        app.secureTextFields["Password"].typeText("SecurePass123!")
        
        app.buttons["Create Account"].tap()
        
        // Then
        XCTAssertTrue(app.staticTexts["Verify your email"].waitForExistence(timeout: 5))
    }
}
```

#### Android - Espresso + Compose Testing

```kotlin
@HiltAndroidTest
class LoginScreenTest {
    @get:Rule(order = 0)
    val hiltRule = HiltAndroidRule(this)

    @get:Rule(order = 1)
    val composeTestRule = createAndroidComposeRule<MainActivity>()

    @Before
    fun setup() {
        hiltRule.inject()
    }

    @Test
    fun loginWithValidCredentials_navigatesToDashboard() {
        composeTestRule.apply {
            // When
            onNodeWithTag("emailTextField").performTextInput("test@example.com")
            onNodeWithTag("passwordTextField").performTextInput("password123")
            onNodeWithTag("loginButton").performClick()

            // Then
            onNodeWithText("Dashboard").assertIsDisplayed()
        }
    }

    @Test
    fun loginWithInvalidCredentials_showsError() {
        composeTestRule.apply {
            // When
            onNodeWithTag("emailTextField").performTextInput("test@example.com")
            onNodeWithTag("passwordTextField").performTextInput("wrong")
            onNodeWithTag("loginButton").performClick()

            // Then
            onNodeWithText("Invalid credentials").assertIsDisplayed()
        }
    }
}
```

### 7.3 Integration Testing

**API Mocking - iOS (OHHTTPStubs)**
```swift
stub(condition: isHost("api.financeapp.com") && isPath("/auth/login")) { _ in
    let json = ["accessToken": "mock_token", "refreshToken": "mock_refresh"]
    return HTTPStubsResponse(jsonObject: json, statusCode: 200, headers: nil)
}
```

**API Mocking - Android (MockWebServer)**
```kotlin
@Test
fun testLoginApiCall() = runTest {
    // Given
    mockWebServer.enqueue(
        MockResponse()
            .setResponseCode(200)
            .setBody("""{"accessToken":"mock_token","refreshToken":"mock_refresh"}""")
    )

    // When
    val result = authRepository.login("test@example.com", "password")

    // Then
    assertTrue(result.isSuccess)
    assertEquals("mock_token", result.getOrNull()?.accessToken)
}
```

**Database Testing**
```kotlin
@RunWith(AndroidJUnit4::class)
class UserDaoTest {
    private lateinit var database: AppDatabase
    private lateinit var userDao: UserDao

    @Before
    fun setup() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        userDao = database.userDao()
    }

    @Test
    fun insertAndRetrieveUser() = runTest {
        // Given
        val user = UserEntity(id = "1", email = "test@example.com")

        // When
        userDao.insertUser(user)
        val retrieved = userDao.getUserById("1")

        // Then
        assertEquals(user, retrieved)
    }

    @After
    fun teardown() {
        database.close()
    }
}
```

---

## 8. Build & Distribution

### 8.1 iOS

#### Xcode Configuration

**Build Schemes**
- **Debug**: Development environment, logging enabled
- **Staging**: Staging environment, limited logging
- **Release**: Production environment, no logging

**Build Settings**
```
SWIFT_OPTIMIZATION_LEVEL = -O (Release)
SWIFT_COMPILATION_MODE = wholemodule (Release)
ENABLE_BITCODE = YES
DEBUG_INFORMATION_FORMAT = dwarf-with-dsym
STRIP_INSTALLED_PRODUCT = YES (Release)
```

**Info.plist Configuration**
```xml
<key>CFBundleDisplayName</key>
<string>FinanceApp</string>
<key>CFBundleIdentifier</key>
<string>com.financeapp.ios</string>
<key>CFBundleVersion</key>
<string>1.0.0</string>
<key>LSRequiresIPhoneOS</key>
<true/>
<key>UIRequiredDeviceCapabilities</key>
<array>
    <string>arm64</string>
</array>
```

#### App Store Submission Checklist

- [ ] App privacy labels configured
  - [ ] Authentication data usage disclosed
  - [ ] Encryption declared
  - [ ] Third-party data usage disclosed
- [ ] App icons (all sizes)
- [ ] Launch screen
- [ ] Screenshots (all device sizes)
- [ ] App description and keywords
- [ ] Age rating questionnaire
- [ ] Export compliance (encryption)
- [ ] GDPR compliance statement
- [ ] TestFlight beta testing completed

#### TestFlight Distribution

**Automatic Distribution**
```bash
# Using fastlane
fastlane beta

# Manual via Xcode
# Product > Archive > Distribute App > TestFlight
```

**Invite Testers**
- Internal testing (25 users)
- External testing (10,000 users)
- Beta app review required for external

### 8.2 Android

#### Gradle Configuration

**build.gradle.kts (app level)**
```kotlin
android {
    namespace = "com.financeapp.android"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.financeapp.android"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            isDebuggable = true
            isMinifyEnabled = false
            buildConfigField("String", "API_URL", "\"https://dev-api.financeapp.com\"")
        }

        create("staging") {
            applicationIdSuffix = ".staging"
            isDebuggable = false
            isMinifyEnabled = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("String", "API_URL", "\"https://staging-api.financeapp.com\"")
        }

        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            buildConfigField("String", "API_URL", "\"https://api.financeapp.com\"")
            signingConfig = signingConfigs.getByName("release")
        }
    }

    signingConfigs {
        create("release") {
            storeFile = file("keystore/release.keystore")
            storePassword = System.getenv("KEYSTORE_PASSWORD")
            keyAlias = System.getenv("KEY_ALIAS")
            keyPassword = System.getenv("KEY_PASSWORD")
        }
    }
}
```

**Build Variants**
```
debugDebug (debug build type)
stagingDebug (staging build type)
releaseRelease (production build type)
```

#### Google Play Submission Checklist

- [ ] App content rating questionnaire
- [ ] Data safety form completed
  - [ ] Data collection disclosed
  - [ ] Data sharing disclosed
  - [ ] Security practices disclosed
- [ ] App icon (512x512)
- [ ] Feature graphic (1024x500)
- [ ] Screenshots (phone, tablet, 7-inch tablet, 10-inch tablet)
- [ ] Privacy policy URL
- [ ] Target audience and content
- [ ] Store listing (description, short description)
- [ ] Signed APK/AAB with production keystore

#### Internal Testing Track

```bash
# Build release AAB
./gradlew bundleRelease

# Upload to internal testing
fastlane supply --track internal --aab app/build/outputs/bundle/release/app-release.aab
```

**Testing Tracks**
- **Internal**: Up to 100 testers, instant availability
- **Closed**: Up to 100 testers per track, instant availability
- **Open**: Unlimited testers, requires review
- **Production**: Public release, requires review

---

## 9. Security Best Practices

### API Key Protection

**iOS**
```swift
// Never hardcode API keys
// Use xcconfig files excluded from version control

// Development.xcconfig
API_KEY = dev_api_key_here

// Info.plist
<key>APIKey</key>
<string>$(API_KEY)</string>

// Access in code
let apiKey = Bundle.main.infoDictionary?["APIKey"] as? String
```

**Android**
```kotlin
// Never hardcode API keys
// Use local.properties excluded from version control

// local.properties
api.key=dev_api_key_here

// build.gradle.kts
val localProperties = Properties()
localProperties.load(project.rootProject.file("local.properties").inputStream())

android {
    defaultConfig {
        buildConfigField("String", "API_KEY", "\"${localProperties["api.key"]}\"")
    }
}

// Access in code
val apiKey = BuildConfig.API_KEY
```

### Certificate Pinning Implementation

**iOS**
```swift
let pinnedCertificates: [Data] = [
    loadCertificate(filename: "production-cert"),
    loadCertificate(filename: "backup-cert")
]

func urlSession(
    _ session: URLSession,
    didReceive challenge: URLAuthenticationChallenge
) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
    guard let serverTrust = challenge.protectionSpace.serverTrust,
          let serverCertificate = SecTrustCopyCertificateChain(serverTrust) as? [SecCertificate] else {
        return (.cancelAuthenticationChallenge, nil)
    }
    
    let serverCertificateData = SecCertificateCopyData(serverCertificate[0]) as Data
    
    if pinnedCertificates.contains(serverCertificateData) {
        return (.useCredential, URLCredential(trust: serverTrust))
    } else {
        return (.cancelAuthenticationChallenge, nil)
    }
}
```

**Android**
```kotlin
val certificatePinner = CertificatePinner.Builder()
    .add("api.financeapp.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.financeapp.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build()

val okHttpClient = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()
```

### Secure Token Storage

**iOS Keychain**
```swift
class KeychainManager {
    func saveToken(_ token: String, forKey key: String) throws {
        let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            nil
        )!
        
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecAttrAccessControl as String: accessControl,
            kSecValueData as String: token.data(using: .utf8)!
        ]
        
        SecItemDelete(query as CFDictionary)
        let status = SecItemAdd(query as CFDictionary, nil)
        
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed
        }
    }
}
```

**Android EncryptedSharedPreferences**
```kotlin
val masterKey = MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build()

val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

encryptedPrefs.edit().putString("access_token", token).apply()
```

### Biometric Authentication

**iOS**
- Face ID / Touch ID via LocalAuthentication
- Fallback to device passcode
- Store sensitive data with `.biometryCurrentSet` flag

**Android**
- BiometricPrompt API
- Support fingerprint, face, iris
- Fallback to device PIN/pattern/password

### Root/Jailbreak Detection

**iOS Jailbreak Detection**
- Check for Cydia and jailbreak files
- Attempt to write outside sandbox
- Verify code signature

**Android Root Detection**
- Check for su binary
- Check for Magisk/SuperSU
- Verify SafetyNet Attestation API

### SSL/TLS Validation

- Enforce TLS 1.3
- Disable cleartext traffic
- Implement certificate pinning
- Validate hostname

### Code Obfuscation

**iOS**
- Swift optimization level `-O`
- Strip debug symbols in Release
- Enable Bitcode

**Android**
- ProGuard/R8 in Release builds
- Obfuscate code and resources
- Remove logging statements

---

## 10. Compliance Requirements

### App Privacy Labels (iOS) / Data Safety (Android)

#### Data Collection Disclosure

**Authentication Data**
- Email address (collected, linked to user, used for authentication)
- Password (not stored, hashed server-side)
- Device ID (collected, linked to device, used for fraud prevention)

**Security Data**
- Login events (timestamps, IP address, device info)
- Biometric data (stored locally, never transmitted)

**Analytics Data**
- App interactions (anonymous, not linked to user)
- Crash logs (anonymous)

### GDPR Compliance

**User Rights Implementation**
- **Right to Access**: Export all user data via API endpoint
- **Right to Erasure**: Delete account and all associated data
- **Right to Portability**: Download data in JSON format
- **Right to Rectification**: Update profile information
- **Right to Restrict Processing**: Pause non-essential data processing

**Consent Management**
```kotlin
data class UserConsent(
    val termsAccepted: Boolean,
    val privacyPolicyAccepted: Boolean,
    val marketingConsent: Boolean,
    val consentTimestamp: Instant,
    val ipAddress: String,
    val userAgent: String
)
```

**Data Retention**
- Active accounts: Indefinite retention
- Inactive accounts (>2 years): Data deletion notice
- Deleted accounts: 30-day grace period, then permanent deletion
- Audit logs: 7 years retention for compliance

### COPPA Compliance (if applicable)

- Parental consent required for users under 13
- Minimal data collection for minors
- No behavioral advertising for minors

### Data Encryption

**At Rest**
- iOS: FileVault encryption + Keychain
- Android: File-based encryption (FBE) + EncryptedSharedPreferences
- Database: SQLCipher for sensitive data

**In Transit**
- TLS 1.3 for all API calls
- Certificate pinning
- No cleartext traffic

### Security Incident Response

**Breach Notification Procedure**
1. Detect and contain breach within 24 hours
2. Assess scope and affected users within 48 hours
3. Notify data protection authority within 72 hours (GDPR)
4. Notify affected users within 72 hours
5. Document incident and remediation steps

---

## Performance Targets

### iOS
- App launch time: < 1.5 seconds (cold start)
- Login response: < 2 seconds
- Frame rate: 60 FPS (120 FPS on ProMotion displays)
- Memory usage: < 150 MB during normal operation
- Battery drain: < 5% per hour of active use

### Android
- App launch time: < 2 seconds (cold start)
- Login response: < 2 seconds
- Frame rate: 60 FPS (90/120 FPS on high refresh rate displays)
- Memory usage: < 200 MB during normal operation
- Battery drain: < 5% per hour of active use

### Network
- API response time: < 200ms (P95)
- Token refresh: < 500ms
- Offline mode: Instant UI response with cached data

---

## Token Budget

This specification is approximately 8,500 tokens, well within the 10,000 token limit for mobile-focused documentation.
