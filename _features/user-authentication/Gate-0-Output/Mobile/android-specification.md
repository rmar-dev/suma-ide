---
layout: default
title: Android Specification
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# Android Mobile Specification - SUMA Finance

## Project: SUMA Finance
## Feature: User Registration & Authentication
## Version: 1.0.0
## Date: 2025-11-01

---

## 1. Android Platform Overview

### Platform Requirements
- **Minimum SDK**: API 24 (Android 7.0 Nougat)
- **Target SDK**: API 34 (Android 14)
- **Compile SDK**: API 34
- **Device Compatibility**: Phone, Tablet, Foldable devices
- **Screen Support**: Small (320dp), Normal (360dp), Large (600dp), XLarge (960dp)
- **Play Store Requirements**: 
  - Android App Bundle (AAB) format
  - Privacy Policy URL
  - Data safety declaration
  - Target API 33+ requirement

### Rationale
- API 24 covers 98%+ of active Android devices
- API 34 provides latest security and performance features
- Financial app requires security features introduced in API 24+

---

## 2. Android Architecture

### Architecture Pattern: Clean Architecture + MVVM

```
┌─────────────────────────────────────────┐
│         Presentation Layer              │
│  (Activities, Fragments, Composables)   │
│              ViewModel                  │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│          Domain Layer                   │
│    (Use Cases, Domain Models)           │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│           Data Layer                    │
│  (Repositories, DataSources, APIs)      │
└─────────────────────────────────────────┘
```

### Project Structure: Multi-Module Architecture

```
suma-finance-android/
├── app/                          # Main application module
├── core/
│   ├── common/                   # Common utilities, extensions
│   ├── design-system/            # UI components, theming
│   ├── network/                  # Networking layer
│   ├── database/                 # Local persistence
│   ├── security/                 # Security utilities
│   └── testing/                  # Test utilities
├── feature/
│   ├── auth/                     # Authentication feature
│   │   ├── ui/                   # Composables & ViewModels
│   │   ├── domain/               # Use cases
│   │   └── data/                 # Repository, API
│   └── registration/             # Registration feature
│       ├── ui/
│       ├── domain/
│       └── data/
└── buildSrc/                     # Gradle dependencies management
```

### Navigation Pattern
- **Jetpack Navigation Component** with Compose Navigation
- Single Activity architecture
- Type-safe navigation with Kotlin DSL

### Dependency Injection
- **Hilt** (Dagger 2 based)
  - Compile-time dependency injection
  - Android-specific annotations
  - ViewModel injection support

### Modularization Strategy
- **Feature modules**: Independent, vertically sliced features
- **Core modules**: Shared infrastructure and utilities
- **Data layer**: Centralized data access
- Clear module dependencies (feature → domain → data)

---

## 3. UI Framework Selection

### Framework: 100% Jetpack Compose

**Rationale:**
- Modern declarative UI
- Type-safe UI development
- Better state management
- Reduced boilerplate
- Future-proof (Google's recommended approach)
- Better testing capabilities

### Material Design Implementation
- **Material Design 3** (Material You)
- Dynamic color theming
- Adaptive layouts for tablets and foldables

### Theme Configuration

```kotlin
// Theme.kt
@Composable
fun SumaFinanceTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) 
            else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

private val LightColorScheme = lightColorScheme(
    primary = Color(0xFF006C4C),        // Financial green
    onPrimary = Color(0xFFFFFFFF),
    primaryContainer = Color(0xFF89F8C7),
    secondary = Color(0xFF4D6357),
    background = Color(0xFFFBFDF9),
    surface = Color(0xFFFBFDF9),
    error = Color(0xFFBA1A1A)
)

private val DarkColorScheme = darkColorScheme(
    primary = Color(0xFF6CDBAC),
    onPrimary = Color(0xFF003826),
    primaryContainer = Color(0xFF005138),
    secondary = Color(0xFFB1CCB3),
    background = Color(0xFF191C1A),
    surface = Color(0xFF191C1A),
    error = Color(0xFFFFB4AB)
)
```

### Typography

```kotlin
val Typography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Default,
        fontWeight = FontWeight.Normal,
        fontSize = 57.sp,
        lineHeight = 64.sp
    ),
    headlineMedium = TextStyle(
        fontWeight = FontWeight.SemiBold,
        fontSize = 28.sp,
        lineHeight = 36.sp
    ),
    bodyLarge = TextStyle(
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 24.sp
    ),
    labelLarge = TextStyle(
        fontWeight = FontWeight.Medium,
        fontSize = 14.sp,
        lineHeight = 20.sp
    )
)
```

---

## 4. Screen Specifications

### 4.1 Splash Screen

**Purpose**: Initial loading, token validation, routing decision

**Implementation:**
- Android 12+ SplashScreen API
- ViewModel for authentication check
- Navigation decision based on auth state

```kotlin
// SplashScreen.kt
@Composable
fun SplashScreen(
    viewModel: SplashViewModel = hiltViewModel(),
    onNavigateToAuth: () -> Unit,
    onNavigateToHome: () -> Unit
) {
    val authState by viewModel.authState.collectAsStateWithLifecycle()

    LaunchedEffect(authState) {
        when (authState) {
            is AuthState.Authenticated -> onNavigateToHome()
            is AuthState.Unauthenticated -> onNavigateToAuth()
            AuthState.Loading -> { /* Show splash */ }
        }
    }

    Box(
        modifier = Modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        Image(
            painter = painterResource(R.drawable.logo),
            contentDescription = "SUMA Finance Logo"
        )
    }
}

// SplashViewModel.kt
@HiltViewModel
class SplashViewModel @Inject constructor(
    private val validateTokenUseCase: ValidateTokenUseCase
) : ViewModel() {
    
    private val _authState = MutableStateFlow<AuthState>(AuthState.Loading)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    init {
        validateAuthStatus()
    }

    private fun validateAuthStatus() {
        viewModelScope.launch {
            _authState.value = try {
                val isValid = validateTokenUseCase()
                if (isValid) AuthState.Authenticated 
                else AuthState.Unauthenticated
            } catch (e: Exception) {
                AuthState.Unauthenticated
            }
        }
    }
}
```

### 4.2 Welcome Screen

**Purpose**: Onboarding, login/register options

**UI Components:**
- App logo and tagline
- "Login" button (primary)
- "Create Account" button (secondary)
- Terms & Privacy links

```kotlin
@Composable
fun WelcomeScreen(
    onLoginClick: () -> Unit,
    onRegisterClick: () -> Unit,
    onTermsClick: () -> Unit,
    onPrivacyClick: () -> Unit
) {
    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            Spacer(modifier = Modifier.height(48.dp))
            
            // Logo Section
            Column(
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Image(
                    painter = painterResource(R.drawable.logo_large),
                    contentDescription = "SUMA Finance",
                    modifier = Modifier.size(120.dp)
                )
                Spacer(modifier = Modifier.height(24.dp))
                Text(
                    text = "SUMA Finance",
                    style = MaterialTheme.typography.headlineLarge
                )
                Text(
                    text = "Smart financial management",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            // Action Buttons
            Column(
                modifier = Modifier.fillMaxWidth()
            ) {
                Button(
                    onClick = onLoginClick,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Login")
                }
                Spacer(modifier = Modifier.height(12.dp))
                OutlinedButton(
                    onClick = onRegisterClick,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Create Account")
                }
                
                // Terms & Privacy
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(top = 24.dp),
                    horizontalArrangement = Arrangement.Center
                ) {
                    TextButton(onClick = onTermsClick) {
                        Text("Terms", fontSize = 12.sp)
                    }
                    Text(" • ", modifier = Modifier.padding(horizontal = 4.dp))
                    TextButton(onClick = onPrivacyClick) {
                        Text("Privacy", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}
```

### 4.3 Registration Screen

**Purpose**: New user account creation

**UI Components:**
- Email input field
- Password input field (with visibility toggle)
- Confirm password field
- Terms & conditions checkbox
- "Create Account" button
- "Already have an account?" link

**State Management:**

```kotlin
@HiltViewModel
class RegistrationViewModel @Inject constructor(
    private val registerUseCase: RegisterUseCase,
    private val validateEmailUseCase: ValidateEmailUseCase,
    private val validatePasswordUseCase: ValidatePasswordUseCase
) : ViewModel() {

    private val _uiState = MutableStateFlow(RegistrationUiState())
    val uiState: StateFlow<RegistrationUiState> = _uiState.asStateFlow()

    fun onEmailChange(email: String) {
        _uiState.update { it.copy(
            email = email,
            emailError = null
        )}
    }

    fun onPasswordChange(password: String) {
        _uiState.update { it.copy(
            password = password,
            passwordError = null
        )}
    }

    fun onConfirmPasswordChange(confirmPassword: String) {
        _uiState.update { it.copy(
            confirmPassword = confirmPassword,
            confirmPasswordError = null
        )}
    }

    fun onTermsAcceptedChange(accepted: Boolean) {
        _uiState.update { it.copy(termsAccepted = accepted) }
    }

    fun onRegisterClick() {
        viewModelScope.launch {
            // Validate inputs
            val emailValidation = validateEmailUseCase(_uiState.value.email)
            val passwordValidation = validatePasswordUseCase(_uiState.value.password)
            val passwordsMatch = _uiState.value.password == _uiState.value.confirmPassword

            if (!emailValidation.isValid || !passwordValidation.isValid || !passwordsMatch) {
                _uiState.update { state ->
                    state.copy(
                        emailError = emailValidation.error,
                        passwordError = passwordValidation.error,
                        confirmPasswordError = if (!passwordsMatch) "Passwords don't match" else null
                    )
                }
                return@launch
            }

            if (!_uiState.value.termsAccepted) {
                _uiState.update { it.copy(showTermsError = true) }
                return@launch
            }

            // Proceed with registration
            _uiState.update { it.copy(isLoading = true) }
            
            registerUseCase(
                email = _uiState.value.email,
                password = _uiState.value.password
            ).onSuccess { result ->
                _uiState.update { it.copy(
                    isLoading = false,
                    registrationSuccess = true
                )}
            }.onFailure { error ->
                _uiState.update { it.copy(
                    isLoading = false,
                    errorMessage = error.message
                )}
            }
        }
    }
}

data class RegistrationUiState(
    val email: String = "",
    val password: String = "",
    val confirmPassword: String = "",
    val termsAccepted: Boolean = false,
    val emailError: String? = null,
    val passwordError: String? = null,
    val confirmPasswordError: String? = null,
    val showTermsError: Boolean = false,
    val isLoading: Boolean = false,
    val registrationSuccess: Boolean = false,
    val errorMessage: String? = null
)
```

**Composable:**

```kotlin
@Composable
fun RegistrationScreen(
    viewModel: RegistrationViewModel = hiltViewModel(),
    onNavigateToLogin: () -> Unit,
    onRegistrationSuccess: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    
    LaunchedEffect(uiState.registrationSuccess) {
        if (uiState.registrationSuccess) {
            onRegistrationSuccess()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Create Account") },
                navigationIcon = {
                    IconButton(onClick = onNavigateToLogin) {
                        Icon(Icons.Default.ArrowBack, "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(24.dp)
                .verticalScroll(rememberScrollState())
        ) {
            // Email Field
            OutlinedTextField(
                value = uiState.email,
                onValueChange = viewModel::onEmailChange,
                label = { Text("Email") },
                isError = uiState.emailError != null,
                supportingText = uiState.emailError?.let { { Text(it) } },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Email,
                    imeAction = ImeAction.Next
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Password Field
            var passwordVisible by remember { mutableStateOf(false) }
            OutlinedTextField(
                value = uiState.password,
                onValueChange = viewModel::onPasswordChange,
                label = { Text("Password") },
                isError = uiState.passwordError != null,
                supportingText = uiState.passwordError?.let { { Text(it) } },
                visualTransformation = if (passwordVisible) 
                    VisualTransformation.None 
                else 
                    PasswordVisualTransformation(),
                trailingIcon = {
                    IconButton(onClick = { passwordVisible = !passwordVisible }) {
                        Icon(
                            if (passwordVisible) Icons.Default.Visibility 
                            else Icons.Default.VisibilityOff,
                            contentDescription = "Toggle password visibility"
                        )
                    }
                },
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Next
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(16.dp))

            // Confirm Password Field
            OutlinedTextField(
                value = uiState.confirmPassword,
                onValueChange = viewModel::onConfirmPasswordChange,
                label = { Text("Confirm Password") },
                isError = uiState.confirmPasswordError != null,
                supportingText = uiState.confirmPasswordError?.let { { Text(it) } },
                visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(
                    keyboardType = KeyboardType.Password,
                    imeAction = ImeAction.Done
                ),
                modifier = Modifier.fillMaxWidth()
            )

            Spacer(modifier = Modifier.height(24.dp))

            // Terms Checkbox
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.fillMaxWidth()
            ) {
                Checkbox(
                    checked = uiState.termsAccepted,
                    onCheckedChange = viewModel::onTermsAcceptedChange
                )
                Text(
                    text = buildAnnotatedString {
                        append("I agree to the ")
                        withStyle(SpanStyle(color = MaterialTheme.colorScheme.primary)) {
                            append("Terms & Conditions")
                        }
                    },
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
            
            if (uiState.showTermsError) {
                Text(
                    text = "You must accept terms to continue",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 48.dp)
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Register Button
            Button(
                onClick = viewModel::onRegisterClick,
                enabled = !uiState.isLoading,
                modifier = Modifier.fillMaxWidth()
            ) {
                if (uiState.isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = MaterialTheme.colorScheme.onPrimary
                    )
                } else {
                    Text("Create Account")
                }
            }

            // Error Message
            uiState.errorMessage?.let { error ->
                Spacer(modifier = Modifier.height(16.dp))
                Text(
                    text = error,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium
                )
            }

            Spacer(modifier = Modifier.height(24.dp))

            // Login Link
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.Center
            ) {
                Text("Already have an account? ")
                TextButton(onClick = onNavigateToLogin) {
                    Text("Login")
                }
            }
        }
    }
}
```

### 4.4 Login Screen

**Purpose**: Existing user authentication

**UI Components:**
- Email input field
- Password input field (with visibility toggle)
- "Forgot Password?" link
- "Login" button
- Biometric authentication option (if available)
- "Don't have an account?" link

```kotlin
@HiltViewModel
class LoginViewModel @Inject constructor(
    private val loginUseCase: LoginUseCase,
    private val biometricManager: BiometricManager,
    private val secureStorage: SecureStorage
) : ViewModel() {

    private val _uiState = MutableStateFlow(LoginUiState())
    val uiState: StateFlow<LoginUiState> = _uiState.asStateFlow()

    val isBiometricAvailable: Boolean
        get() = biometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS

    fun onEmailChange(email: String) {
        _uiState.update { it.copy(email = email, emailError = null) }
    }

    fun onPasswordChange(password: String) {
        _uiState.update { it.copy(password = password, passwordError = null) }
    }

    fun onLoginClick() {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoading = true, errorMessage = null) }

            loginUseCase(
                email = _uiState.value.email,
                password = _uiState.value.password
            ).onSuccess { authToken ->
                secureStorage.saveAuthToken(authToken)
                _uiState.update { it.copy(
                    isLoading = false,
                    loginSuccess = true
                )}
            }.onFailure { error ->
                _uiState.update { it.copy(
                    isLoading = false,
                    errorMessage = when (error) {
                        is InvalidCredentialsException -> "Invalid email or password"
                        is NetworkException -> "Network error. Please try again."
                        else -> "An error occurred. Please try again."
                    }
                )}
            }
        }
    }

    fun onBiometricAuthSuccess(cryptoObject: BiometricPrompt.CryptoObject?) {
        viewModelScope.launch {
            // Retrieve stored credentials and authenticate
            val credentials = secureStorage.getBiometricCredentials()
            credentials?.let {
                loginUseCase(it.email, it.password)
                    .onSuccess { authToken ->
                        secureStorage.saveAuthToken(authToken)
                        _uiState.update { state -> state.copy(loginSuccess = true) }
                    }
            }
        }
    }
}

data class LoginUiState(
    val email: String = "",
    val password: String = "",
    val emailError: String? = null,
    val passwordError: String? = null,
    val isLoading: Boolean = false,
    val loginSuccess: Boolean = false,
    val errorMessage: String? = null
)
```

### 4.5 Forgot Password Screen

**Purpose**: Password reset flow

**UI Components:**
- Email input field
- "Send Reset Link" button
- Success message display
- Back to login link

### 4.6 Email Verification Screen

**Purpose**: Verify email after registration

**UI Components:**
- Verification message
- Resend verification email button
- Email edit option
- Timer for resend cooldown

---

## 5. Android Components Library

### Navigation Components
```kotlin
// Bottom Navigation (for main app flow)
@Composable
fun MainBottomNavigation(
    navController: NavController,
    currentRoute: String?
) {
    NavigationBar {
        NavigationBarItem(
            icon = { Icon(Icons.Default.Home, "Home") },
            label = { Text("Home") },
            selected = currentRoute == "home",
            onClick = { navController.navigate("home") }
        )
        NavigationBarItem(
            icon = { Icon(Icons.Default.AccountCircle, "Account") },
            label = { Text("Account") },
            selected = currentRoute == "account",
            onClick = { navController.navigate("account") }
        )
    }
}

// Top App Bar with navigation
@Composable
fun SumaTopAppBar(
    title: String,
    onNavigationClick: () -> Unit,
    actions: @Composable RowScope.() -> Unit = {}
) {
    TopAppBar(
        title = { Text(title) },
        navigationIcon = {
            IconButton(onClick = onNavigationClick) {
                Icon(Icons.Default.ArrowBack, "Back")
            }
        },
        actions = actions
    )
}
```

### Input Components
```kotlin
// Reusable text field component
@Composable
fun SumaTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    isError: Boolean = false,
    errorMessage: String? = null,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    visualTransformation: VisualTransformation = VisualTransformation.None,
    leadingIcon: @Composable (() -> Unit)? = null,
    trailingIcon: @Composable (() -> Unit)? = null
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier,
        isError = isError,
        supportingText = errorMessage?.let { { Text(it) } },
        keyboardOptions = keyboardOptions,
        visualTransformation = visualTransformation,
        leadingIcon = leadingIcon,
        trailingIcon = trailingIcon,
        singleLine = true
    )
}

// Password field with visibility toggle
@Composable
fun PasswordTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String = "Password",
    modifier: Modifier = Modifier,
    isError: Boolean = false,
    errorMessage: String? = null
) {
    var passwordVisible by remember { mutableStateOf(false) }

    SumaTextField(
        value = value,
        onValueChange = onValueChange,
        label = label,
        modifier = modifier,
        isError = isError,
        errorMessage = errorMessage,
        visualTransformation = if (passwordVisible) 
            VisualTransformation.None 
        else 
            PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password),
        trailingIcon = {
            IconButton(onClick = { passwordVisible = !passwordVisible }) {
                Icon(
                    if (passwordVisible) Icons.Default.Visibility 
                    else Icons.Default.VisibilityOff,
                    contentDescription = "Toggle password visibility"
                )
            }
        }
    )
}
```

### Feedback Components
```kotlin
// Snackbar for user feedback
@Composable
fun ShowSnackbar(
    snackbarHostState: SnackbarHostState,
    message: String,
    actionLabel: String? = null,
    onActionPerformed: () -> Unit = {}
) {
    LaunchedEffect(message) {
        val result = snackbarHostState.showSnackbar(
            message = message,
            actionLabel = actionLabel,
            duration = SnackbarDuration.Short
        )
        if (result == SnackbarResult.ActionPerformed) {
            onActionPerformed()
        }
    }
}

// Loading indicator
@Composable
fun LoadingIndicator(modifier: Modifier = Modifier) {
    Box(
        modifier = modifier.fillMaxSize(),
        contentAlignment = Alignment.Center
    ) {
        CircularProgressIndicator()
    }
}

// Error display
@Composable
fun ErrorDisplay(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Icon(
            Icons.Default.Error,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.error,
            modifier = Modifier.size(64.dp)
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = message,
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.Center
        )
        Spacer(modifier = Modifier.height(24.dp))
        Button(onClick = onRetry) {
            Text("Retry")
        }
    }
}
```

---

## 6. Data Persistence

### EncryptedSharedPreferences for Auth Tokens

```kotlin
@Singleton
class SecureStorage @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    private val encryptedPrefs = EncryptedSharedPreferences.create(
        context,
        "suma_secure_prefs",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    fun saveAuthToken(token: String) {
        encryptedPrefs.edit()
            .putString(KEY_AUTH_TOKEN, token)
            .apply()
    }

    fun getAuthToken(): String? {
        return encryptedPrefs.getString(KEY_AUTH_TOKEN, null)
    }

    fun clearAuthToken() {
        encryptedPrefs.edit()
            .remove(KEY_AUTH_TOKEN)
            .apply()
    }

    fun saveBiometricCredentials(email: String, encryptedPassword: String) {
        encryptedPrefs.edit()
            .putString(KEY_BIOMETRIC_EMAIL, email)
            .putString(KEY_BIOMETRIC_PASSWORD, encryptedPassword)
            .apply()
    }

    fun getBiometricCredentials(): BiometricCredentials? {
        val email = encryptedPrefs.getString(KEY_BIOMETRIC_EMAIL, null)
        val password = encryptedPrefs.getString(KEY_BIOMETRIC_PASSWORD, null)
        return if (email != null && password != null) {
            BiometricCredentials(email, password)
        } else null
    }

    companion object {
        private const val KEY_AUTH_TOKEN = "auth_token"
        private const val KEY_BIOMETRIC_EMAIL = "biometric_email"
        private const val KEY_BIOMETRIC_PASSWORD = "biometric_password"
    }
}

data class BiometricCredentials(val email: String, val password: String)
```

### DataStore for App Preferences

```kotlin
val Context.dataStore: DataStore<Preferences> by preferencesDataStore(name = "suma_settings")

@Singleton
class UserPreferencesRepository @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val dataStore = context.dataStore

    val userPreferences: Flow<UserPreferences> = dataStore.data
        .catch { exception ->
            if (exception is IOException) {
                emit(emptyPreferences())
            } else {
                throw exception
            }
        }
        .map { preferences ->
            UserPreferences(
                biometricEnabled = preferences[BIOMETRIC_ENABLED] ?: false,
                notificationsEnabled = preferences[NOTIFICATIONS_ENABLED] ?: true,
                theme = preferences[THEME] ?: "system"
            )
        }

    suspend fun updateBiometricEnabled(enabled: Boolean) {
        dataStore.edit { preferences ->
            preferences[BIOMETRIC_ENABLED] = enabled
        }
    }

    companion object {
        private val BIOMETRIC_ENABLED = booleanPreferencesKey("biometric_enabled")
        private val NOTIFICATIONS_ENABLED = booleanPreferencesKey("notifications_enabled")
        private val THEME = stringPreferencesKey("theme")
    }
}

data class UserPreferences(
    val biometricEnabled: Boolean,
    val notificationsEnabled: Boolean,
    val theme: String
)
```

---

## 7. Networking Layer

### Retrofit Configuration

```kotlin
// Module: core:network

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    @Provides
    @Singleton
    fun provideOkHttpClient(
        authInterceptor: AuthInterceptor,
        loggingInterceptor: HttpLoggingInterceptor
    ): OkHttpClient {
        return OkHttpClient.Builder()
            .addInterceptor(authInterceptor)
            .addInterceptor(loggingInterceptor)
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(30, TimeUnit.SECONDS)
            .certificatePinner(getCertificatePinner()) // SSL pinning
            .build()
    }

    @Provides
    @Singleton
    fun provideLoggingInterceptor(): HttpLoggingInterceptor {
        return HttpLoggingInterceptor().apply {
            level = if (BuildConfig.DEBUG) 
                HttpLoggingInterceptor.Level.BODY 
            else 
                HttpLoggingInterceptor.Level.NONE
        }
    }

    @Provides
    @Singleton
    fun provideRetrofit(okHttpClient: OkHttpClient): Retrofit {
        return Retrofit.Builder()
            .baseUrl(BuildConfig.API_BASE_URL)
            .client(okHttpClient)
            .addConverterFactory(GsonConverterFactory.create())
            .build()
    }

    @Provides
    @Singleton
    fun provideAuthApi(retrofit: Retrofit): AuthApi {
        return retrofit.create(AuthApi::class.java)
    }

    private fun getCertificatePinner(): CertificatePinner {
        return CertificatePinner.Builder()
            .add("api.sumafinance.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .build()
    }
}

// AuthInterceptor.kt
@Singleton
class AuthInterceptor @Inject constructor(
    private val secureStorage: SecureStorage
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val token = secureStorage.getAuthToken()

        val newRequest = if (token != null) {
            originalRequest.newBuilder()
                .header("Authorization", "Bearer $token")
                .build()
        } else {
            originalRequest
        }

        return chain.proceed(newRequest)
    }
}
```

### API Definitions

```kotlin
interface AuthApi {
    @POST("auth/register")
    suspend fun register(@Body request: RegisterRequest): Response<AuthResponse>

    @POST("auth/login")
    suspend fun login(@Body request: LoginRequest): Response<AuthResponse>

    @POST("auth/verify-email")
    suspend fun verifyEmail(@Body request: VerifyEmailRequest): Response<Unit>

    @POST("auth/resend-verification")
    suspend fun resendVerification(@Body request: ResendVerificationRequest): Response<Unit>

    @POST("auth/forgot-password")
    suspend fun forgotPassword(@Body request: ForgotPasswordRequest): Response<Unit>

    @POST("auth/reset-password")
    suspend fun resetPassword(@Body request: ResetPasswordRequest): Response<Unit>

    @POST("auth/refresh")
    suspend fun refreshToken(@Body request: RefreshTokenRequest): Response<AuthResponse>
}

// Request/Response Models
@Serializable
data class RegisterRequest(
    val email: String,
    val password: String
)

@Serializable
data class LoginRequest(
    val email: String,
    val password: String
)

@Serializable
data class AuthResponse(
    val token: String,
    val refreshToken: String,
    val expiresIn: Long,
    val user: UserDto
)

@Serializable
data class UserDto(
    val id: String,
    val email: String,
    val emailVerified: Boolean,
    val createdAt: String
)
```

### Error Handling

```kotlin
sealed class NetworkResult<out T> {
    data class Success<T>(val data: T) : NetworkResult<T>()
    data class Error(val exception: NetworkException) : NetworkResult<Nothing>()
    object Loading : NetworkResult<Nothing>()
}

sealed class NetworkException : Exception() {
    data class HttpException(val code: Int, override val message: String) : NetworkException()
    data class NetworkError(override val message: String) : NetworkException()
    data class UnknownError(override val message: String) : NetworkException()
}

suspend fun <T> safeApiCall(apiCall: suspend () -> Response<T>): NetworkResult<T> {
    return try {
        val response = apiCall()
        if (response.isSuccessful) {
            response.body()?.let {
                NetworkResult.Success(it)
            } ?: NetworkResult.Error(NetworkException.UnknownError("Empty response body"))
        } else {
            NetworkResult.Error(
                NetworkException.HttpException(
                    code = response.code(),
                    message = response.message()
                )
            )
        }
    } catch (e: IOException) {
        NetworkResult.Error(NetworkException.NetworkError("Network error: ${e.message}"))
    } catch (e: Exception) {
        NetworkResult.Error(NetworkException.UnknownError("Unknown error: ${e.message}"))
    }
}
```

---

## 8. State Management

### ViewModel + StateFlow Pattern

```kotlin
@HiltViewModel
class AuthViewModel @Inject constructor(
    private val loginUseCase: LoginUseCase,
    private val registerUseCase: RegisterUseCase,
    private val logoutUseCase: LogoutUseCase
) : ViewModel() {

    private val _authState = MutableStateFlow<AuthState>(AuthState.Unauthenticated)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    private val _events = MutableSharedFlow<AuthEvent>()
    val events: SharedFlow<AuthEvent> = _events.asSharedFlow()

    fun login(email: String, password: String) {
        viewModelScope.launch {
            _authState.value = AuthState.Loading
            
            loginUseCase(email, password)
                .onSuccess { user ->
                    _authState.value = AuthState.Authenticated(user)
                    _events.emit(AuthEvent.LoginSuccess)
                }
                .onFailure { error ->
                    _authState.value = AuthState.Error(error.message ?: "Login failed")
                    _events.emit(AuthEvent.LoginError(error.message ?: "Unknown error"))
                }
        }
    }

    fun logout() {
        viewModelScope.launch {
            logoutUseCase()
            _authState.value = AuthState.Unauthenticated
            _events.emit(AuthEvent.LogoutSuccess)
        }
    }
}

sealed class AuthState {
    object Unauthenticated : AuthState()
    object Loading : AuthState()
    data class Authenticated(val user: User) : AuthState()
    data class Error(val message: String) : AuthState()
}

sealed class AuthEvent {
    object LoginSuccess : AuthEvent()
    data class LoginError(val message: String) : AuthEvent()
    object LogoutSuccess : AuthEvent()
}
```

### Compose State Management

```kotlin
@Composable
fun LoginScreenStateful(
    viewModel: LoginViewModel = hiltViewModel(),
    onNavigateToHome: () -> Unit,
    onNavigateToRegister: () -> Unit
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    // Event handling
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is AuthEvent.LoginSuccess -> onNavigateToHome()
                is AuthEvent.LoginError -> {
                    snackbarHostState.showSnackbar(event.message)
                }
                else -> {}
            }
        }
    }

    LoginScreenStateless(
        uiState = uiState,
        snackbarHostState = snackbarHostState,
        onEmailChange = viewModel::onEmailChange,
        onPasswordChange = viewModel::onPasswordChange,
        onLoginClick = viewModel::onLoginClick,
        onRegisterClick = onNavigateToRegister
    )
}

@Composable
fun LoginScreenStateless(
    uiState: LoginUiState,
    snackbarHostState: SnackbarHostState,
    onEmailChange: (String) -> Unit,
    onPasswordChange: (String) -> Unit,
    onLoginClick: () -> Unit,
    onRegisterClick: () -> Unit
) {
    Scaffold(
        snackbarHost = { SnackbarHost(snackbarHostState) }
    ) { padding ->
        // UI implementation
    }
}
```

---

## 9. Background Tasks

### WorkManager for Token Refresh

```kotlin
class TokenRefreshWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        return try {
            val secureStorage = SecureStorage(applicationContext)
            val authApi = // Inject or create AuthApi

            val refreshToken = secureStorage.getRefreshToken()
            if (refreshToken != null) {
                val response = authApi.refreshToken(RefreshTokenRequest(refreshToken))
                if (response.isSuccessful) {
                    response.body()?.let { authResponse ->
                        secureStorage.saveAuthToken(authResponse.token)
                        secureStorage.saveRefreshToken(authResponse.refreshToken)
                        Result.success()
                    } ?: Result.failure()
                } else {
                    Result.failure()
                }
            } else {
                Result.failure()
            }
        } catch (e: Exception) {
            Result.retry()
        }
    }
}

// Schedule periodic token refresh
class TokenRefreshScheduler @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun scheduleTokenRefresh() {
        val constraints = Constraints.Builder()
            .setRequiredNetworkType(NetworkType.CONNECTED)
            .build()

        val refreshRequest = PeriodicWorkRequestBuilder<TokenRefreshWorker>(
            repeatInterval = 6,
            repeatIntervalTimeUnit = TimeUnit.HOURS
        )
            .setConstraints(constraints)
            .build()

        WorkManager.getInstance(context)
            .enqueueUniquePeriodicWork(
                "token_refresh",
                ExistingPeriodicWorkPolicy.KEEP,
                refreshRequest
            )
    }
}
```

---

## 10. Push Notifications

### Firebase Cloud Messaging Setup

```kotlin
// build.gradle.kts (app module)
dependencies {
    implementation(platform("com.google.firebase:firebase-bom:32.7.0"))
    implementation("com.google.firebase:firebase-messaging-ktx")
}

// FirebaseMessagingService
class SumaFirebaseMessagingService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        super.onNewToken(token)
        // Send token to backend
        sendTokenToServer(token)
    }

    override fun onMessageReceived(remoteMessage: RemoteMessage) {
        super.onMessageReceived(remoteMessage)

        remoteMessage.notification?.let { notification ->
            showNotification(
                title = notification.title ?: "",
                message = notification.body ?: "",
                data = remoteMessage.data
            )
        }
    }

    private fun showNotification(title: String, message: String, data: Map<String, String>) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        // Create notification channel (required for API 26+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "SUMA Notifications",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Financial alerts and updates"
            }
            notificationManager.createNotificationChannel(channel)
        }

        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra("notification_data", data.toString())
        }

        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE
        )

        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_notification)
            .setContentTitle(title)
            .setContentText(message)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setContentIntent(pendingIntent)
            .setAutoCancel(true)
            .build()

        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    companion object {
        private const val CHANNEL_ID = "suma_notifications"
        private const val NOTIFICATION_ID = 1001
    }
}
```

### Notification Permission (API 33+)

```kotlin
@Composable
fun RequestNotificationPermission() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
        val permissionState = rememberPermissionState(
            android.Manifest.permission.POST_NOTIFICATIONS
        )

        LaunchedEffect(Unit) {
            if (!permissionState.hasPermission) {
                permissionState.launchPermissionRequest()
            }
        }
    }
}
```

---

## 11. Deep Linking

### App Links Configuration

```xml
<!-- AndroidManifest.xml -->
<activity
    android:name=".MainActivity"
    android:exported="true">
    
    <!-- Default launcher intent -->
    <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
    </intent-filter>

    <!-- App Links for email verification -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="https"
            android:host="sumafinance.com"
            android:pathPrefix="/verify" />
    </intent-filter>

    <!-- App Links for password reset -->
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="https"
            android:host="sumafinance.com"
            android:pathPrefix="/reset-password" />
    </intent-filter>

    <!-- Deep Links (custom scheme) -->
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="sumafinance" />
    </intent-filter>
</activity>
```

### Deep Link Handling in Compose

```kotlin
@Composable
fun SumaNavHost(
    navController: NavHostController,
    startDestination: String
) {
    NavHost(
        navController = navController,
        startDestination = startDestination
    ) {
        composable("splash") { SplashScreen(navController) }
        composable("welcome") { WelcomeScreen(navController) }
        composable("login") { LoginScreen(navController) }
        composable("register") { RegistrationScreen(navController) }
        
        // Deep link for email verification
        composable(
            route = "verify-email/{token}",
            arguments = listOf(navArgument("token") { type = NavType.StringType }),
            deepLinks = listOf(
                navDeepLink { uriPattern = "https://sumafinance.com/verify?token={token}" },
                navDeepLink { uriPattern = "sumafinance://verify?token={token}" }
            )
        ) { backStackEntry ->
            val token = backStackEntry.arguments?.getString("token")
            EmailVerificationScreen(navController, token)
        }

        // Deep link for password reset
        composable(
            route = "reset-password/{token}",
            arguments = listOf(navArgument("token") { type = NavType.StringType }),
            deepLinks = listOf(
                navDeepLink { uriPattern = "https://sumafinance.com/reset-password?token={token}" },
                navDeepLink { uriPattern = "sumafinance://reset-password?token={token}" }
            )
        ) { backStackEntry ->
            val token = backStackEntry.arguments?.getString("token")
            ResetPasswordScreen(navController, token)
        }
    }
}
```

---

## 12. Android-Specific Features

### Biometric Authentication

```kotlin
@Singleton
class BiometricAuthManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    private val biometricManager = BiometricManager.from(context)

    fun canAuthenticate(): Int {
        return biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    }

    fun isBiometricAvailable(): Boolean {
        return canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS
    }
}

@Composable
fun BiometricPrompt(
    onAuthSuccess: () -> Unit,
    onAuthError: (String) -> Unit,
    onAuthFailed: () -> Unit
) {
    val context = LocalContext.current
    val executor = remember { ContextCompat.getMainExecutor(context) }

    val biometricPrompt = remember {
        BiometricPrompt(
            context as FragmentActivity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onAuthSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    onAuthError(errString.toString())
                }

                override fun onAuthenticationFailed() {
                    onAuthFailed()
                }
            }
        )
    }

    val promptInfo = remember {
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("Biometric Authentication")
            .setSubtitle("Authenticate to access SUMA Finance")
            .setAllowedAuthenticators(
                BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
            .build()
    }

    DisposableEffect(Unit) {
        biometricPrompt.authenticate(promptInfo)
        onDispose { }
    }
}
```

---

## 13. Performance Optimization

### Image Loading with Coil

```kotlin
// build.gradle.kts
dependencies {
    implementation("io.coil-kt:coil-compose:2.5.0")
}

// Coil setup in Application class
class SumaFinanceApplication : Application(), ImageLoaderFactory {
    override fun newImageLoader(): ImageLoader {
        return ImageLoader.Builder(this)
            .memoryCache {
                MemoryCache.Builder(this)
                    .maxSizePercent(0.25)
                    .build()
            }
            .diskCache {
                DiskCache.Builder()
                    .directory(cacheDir.resolve("image_cache"))
                    .maxSizeBytes(50 * 1024 * 1024) // 50MB
                    .build()
            }
            .respectCacheHeaders(false)
            .build()
    }
}

// Usage in Compose
@Composable
fun UserAvatar(imageUrl: String, modifier: Modifier = Modifier) {
    AsyncImage(
        model = ImageRequest.Builder(LocalContext.current)
            .data(imageUrl)
            .crossfade(true)
            .build(),
        contentDescription = "User avatar",
        contentScale = ContentScale.Crop,
        modifier = modifier.clip(CircleShape)
    )
}
```

### App Startup Optimization

```kotlin
// build.gradle.kts
dependencies {
    implementation("androidx.startup:startup-runtime:1.1.1")
}

// Initialize libraries on background thread
class WorkManagerInitializer : Initializer<WorkManager> {
    override fun create(context: Context): WorkManager {
        val configuration = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()
        WorkManager.initialize(context, configuration)
        return WorkManager.getInstance(context)
    }

    override fun dependencies(): List<Class<out Initializer<*>>> {
        return emptyList()
    }
}

// AndroidManifest.xml
<provider
    android:name="androidx.startup.InitializationProvider"
    android:authorities="${applicationId}.androidx-startup"
    android:exported="false"
    tools:node="merge">
    <meta-data
        android:name="com.suma.finance.WorkManagerInitializer"
        android:value="androidx.startup" />
</provider>
```

---

## 14. Accessibility (TalkBack, Large Text)

### TalkBack Support

```kotlin
@Composable
fun AccessibleButton(
    text: String,
    onClick: () -> Unit,
    contentDescription: String? = null,
    modifier: Modifier = Modifier
) {
    Button(
        onClick = onClick,
        modifier = modifier.semantics {
            this.contentDescription = contentDescription ?: text
            this.role = Role.Button
        }
    ) {
        Text(text)
    }
}

@Composable
fun AccessibleTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier.semantics {
            this.contentDescription = "$label input field"
        }
    )
}
```

### Scalable Text

```kotlin
// Use SP units for text, avoid hardcoded pixel sizes
Text(
    text = "Welcome to SUMA Finance",
    style = MaterialTheme.typography.headlineMedium, // Uses SP internally
    modifier = Modifier.fillMaxWidth()
)

// Minimum touch target: 48dp x 48dp
IconButton(
    onClick = { },
    modifier = Modifier.size(48.dp) // Meets accessibility guidelines
) {
    Icon(Icons.Default.Menu, contentDescription = "Menu")
}
```

---

## 15. Testing Strategy

### Unit Tests (JUnit + MockK)

```kotlin
// LoginViewModelTest.kt
@ExperimentalCoroutinesTest
class LoginViewModelTest {

    @get:Rule
    val instantExecutorRule = InstantTaskExecutorRule()

    @get:Rule
    val mainDispatcherRule = MainDispatcherRule()

    private lateinit var viewModel: LoginViewModel
    private lateinit var loginUseCase: LoginUseCase
    private lateinit var secureStorage: SecureStorage

    @Before
    fun setup() {
        loginUseCase = mockk()
        secureStorage = mockk(relaxed = true)
        viewModel = LoginViewModel(loginUseCase, secureStorage)
    }

    @Test
    fun `login with valid credentials updates state to success`() = runTest {
        // Given
        val email = "test@example.com"
        val password = "Password123!"
        val authToken = "mock_token"
        
        coEvery { loginUseCase(email, password) } returns Result.success(authToken)

        // When
        viewModel.onEmailChange(email)
        viewModel.onPasswordChange(password)
        viewModel.onLoginClick()

        // Then
        advanceUntilIdle()
        assertTrue(viewModel.uiState.value.loginSuccess)
        coVerify { secureStorage.saveAuthToken(authToken) }
    }

    @Test
    fun `login with invalid credentials shows error`() = runTest {
        // Given
        val email = "test@example.com"
        val password = "wrong"
        
        coEvery { loginUseCase(email, password) } returns 
            Result.failure(InvalidCredentialsException())

        // When
        viewModel.onEmailChange(email)
        viewModel.onPasswordChange(password)
        viewModel.onLoginClick()

        // Then
        advanceUntilIdle()
        assertEquals("Invalid email or password", viewModel.uiState.value.errorMessage)
    }
}
```

### Compose UI Tests

```kotlin
// LoginScreenTest.kt
@get:Rule
val composeTestRule = createComposeRule()

@Test
fun loginScreen_displaysAllElements() {
    composeTestRule.setContent {
        SumaFinanceTheme {
            LoginScreen(
                onNavigateToHome = {},
                onNavigateToRegister = {}
            )
        }
    }

    composeTestRule.onNodeWithText("Email").assertIsDisplayed()
    composeTestRule.onNodeWithText("Password").assertIsDisplayed()
    composeTestRule.onNodeWithText("Login").assertIsDisplayed()
    composeTestRule.onNodeWithText("Don't have an account?").assertIsDisplayed()
}

@Test
fun loginScreen_enterCredentials_enablesLoginButton() {
    composeTestRule.setContent {
        SumaFinanceTheme {
            LoginScreen(
                onNavigateToHome = {},
                onNavigateToRegister = {}
            )
        }
    }

    // Enter email
    composeTestRule.onNodeWithText("Email").performTextInput("test@example.com")
    
    // Enter password
    composeTestRule.onNodeWithText("Password").performTextInput("Password123!")

    // Login button should be enabled
    composeTestRule.onNodeWithText("Login").assertIsEnabled()
}
```

### Integration Tests (API Mocking)

```kotlin
@Test
fun loginFlow_withValidCredentials_navigatesToHome() = runTest {
    val mockWebServer = MockWebServer()
    mockWebServer.start()

    // Mock successful login response
    mockWebServer.enqueue(
        MockResponse()
            .setResponseCode(200)
            .setBody("""
                {
                    "token": "mock_token",
                    "refreshToken": "mock_refresh",
                    "expiresIn": 3600,
                    "user": {
                        "id": "123",
                        "email": "test@example.com",
                        "emailVerified": true,
                        "createdAt": "2025-01-01T00:00:00Z"
                    }
                }
            """.trimIndent())
    )

    // Test login flow
    // ...
}
```

### Code Coverage Target
- **Unit Tests**: 80%+ coverage
- **Integration Tests**: Critical paths covered
- **UI Tests**: Major user flows covered

---

## 16. Build & Deployment

### Build Variants & Product Flavors

```kotlin
// build.gradle.kts (app module)
android {
    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-DEBUG"
            isDebuggable = true
            isMinifyEnabled = false
        }
        
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
            signingConfig = signingConfigs.getByName("release")
        }
    }

    flavorDimensions += "environment"
    productFlavors {
        create("dev") {
            dimension = "environment"
            applicationIdSuffix = ".dev"
            versionNameSuffix = "-dev"
            buildConfigField("String", "API_BASE_URL", "\"https://dev-api.sumafinance.com\"")
        }
        
        create("staging") {
            dimension = "environment"
            applicationIdSuffix = ".staging"
            versionNameSuffix = "-staging"
            buildConfigField("String", "API_BASE_URL", "\"https://staging-api.sumafinance.com\"")
        }
        
        create("prod") {
            dimension = "environment"
            buildConfigField("String", "API_BASE_URL", "\"https://api.sumafinance.com\"")
        }
    }
}
```

### ProGuard/R8 Rules

```proguard
# proguard-rules.pro

# Keep data classes used with Gson/Retrofit
-keep class com.suma.finance.data.model.** { *; }
-keepclassmembers class com.suma.finance.data.model.** { *; }

# Retrofit
-keepattributes Signature
-keepattributes *Annotation*
-keep class retrofit2.** { *; }

# OkHttp
-dontwarn okhttp3.**
-keep class okhttp3.** { *; }

# EncryptedSharedPreferences
-keep class androidx.security.crypto.** { *; }
-keep class com.google.crypto.tink.** { *; }

# Kotlin Coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
```

---

## 17. Dependencies & Package Management

### Version Catalog (libs.versions.toml)

```toml
[versions]
agp = "8.2.0"
kotlin = "1.9.21"
compose = "1.5.4"
composeBom = "2024.01.00"
hilt = "2.48.1"
retrofit = "2.9.0"
room = "2.6.1"
lifecycle = "2.7.0"

[libraries]
androidx-core-ktx = { module = "androidx.core:core-ktx", version = "1.12.0" }
androidx-lifecycle-runtime = { module = "androidx.lifecycle:lifecycle-runtime-ktx", version.ref = "lifecycle" }
androidx-activity-compose = { module = "androidx.activity:activity-compose", version = "1.8.2" }

compose-bom = { module = "androidx.compose:compose-bom", version.ref = "composeBom" }
compose-ui = { module = "androidx.compose.ui:ui" }
compose-material3 = { module = "androidx.compose.material3:material3" }
compose-ui-tooling = { module = "androidx.compose.ui:ui-tooling" }

hilt-android = { module = "com.google.dagger:hilt-android", version.ref = "hilt" }
hilt-compiler = { module = "com.google.dagger:hilt-compiler", version.ref = "hilt" }
hilt-navigation-compose = { module = "androidx.hilt:hilt-navigation-compose", version = "1.1.0" }

retrofit = { module = "com.squareup.retrofit2:retrofit", version.ref = "retrofit" }
retrofit-gson = { module = "com.squareup.retrofit2:converter-gson", version.ref = "retrofit" }
okhttp-logging = { module = "com.squareup.okhttp3:logging-interceptor", version = "4.12.0" }

room-runtime = { module = "androidx.room:room-runtime", version.ref = "room" }
room-ktx = { module = "androidx.room:room-ktx", version.ref = "room" }
room-compiler = { module = "androidx.room:room-compiler", version.ref = "room" }

security-crypto = { module = "androidx.security:security-crypto", version = "1.1.0-alpha06" }
datastore-preferences = { module = "androidx.datastore:datastore-preferences", version = "1.0.0" }

biometric = { module = "androidx.biometric:biometric", version = "1.2.0-alpha05" }
work-runtime = { module = "androidx.work:work-runtime-ktx", version = "2.9.0" }

coil-compose = { module = "io.coil-kt:coil-compose", version = "2.5.0" }

firebase-bom = { module = "com.google.firebase:firebase-bom", version = "32.7.0" }
firebase-messaging = { module = "com.google.firebase:firebase-messaging-ktx" }

junit = { module = "junit:junit", version = "4.13.2" }
mockk = { module = "io.mockk:mockk", version = "1.13.9" }
kotlinx-coroutines-test = { module = "org.jetbrains.kotlinx:kotlinx-coroutines-test", version = "1.7.3" }
compose-ui-test = { module = "androidx.compose.ui:ui-test-junit4" }

[plugins]
android-application = { id = "com.android.application", version.ref = "agp" }
kotlin-android = { id = "org.jetbrains.kotlin.android", version.ref = "kotlin" }
hilt = { id = "com.google.dagger.hilt.android", version.ref = "hilt" }
google-services = { id = "com.google.gms.google-services", version = "4.4.0" }
```

### Build Configuration

```kotlin
// build.gradle.kts (app module)
plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.google.services)
    kotlin("kapt")
}

dependencies {
    // Core
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime)
    implementation(libs.androidx.activity.compose)

    // Compose
    implementation(platform(libs.compose.bom))
    implementation(libs.compose.ui)
    implementation(libs.compose.material3)
    debugImplementation(libs.compose.ui.tooling)

    // Hilt
    implementation(libs.hilt.android)
    kapt(libs.hilt.compiler)
    implementation(libs.hilt.navigation.compose)

    // Networking
    implementation(libs.retrofit)
    implementation(libs.retrofit.gson)
    implementation(libs.okhttp.logging)

    // Storage
    implementation(libs.security.crypto)
    implementation(libs.datastore.preferences)

    // Android features
    implementation(libs.biometric)
    implementation(libs.work.runtime)

    // Image loading
    implementation(libs.coil.compose)

    // Firebase
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.messaging)

    // Testing
    testImplementation(libs.junit)
    testImplementation(libs.mockk)
    testImplementation(libs.kotlinx.coroutines.test)
    androidTestImplementation(libs.compose.ui.test)
}
```

---

## 18. Android Security

### Network Security Configuration

```xml
<!-- res/xml/network_security_config.xml -->
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Production configuration -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">api.sumafinance.com</domain>
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <!-- Backup pin -->
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>

    <!-- Debug configuration -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user" />
            <certificates src="system" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
```

```xml
<!-- AndroidManifest.xml -->
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
</application>
```

### Root Detection

```kotlin
@Singleton
class SecurityManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    fun isDeviceRooted(): Boolean {
        return checkRootMethod1() || checkRootMethod2() || checkRootMethod3()
    }

    private fun checkRootMethod1(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkRootMethod2(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        return paths.any { File(it).exists() }
    }

    private fun checkRootMethod3(): Boolean {
        var process: Process? = null
        return try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val input = BufferedReader(InputStreamReader(process.inputStream))
            input.readLine() != null
        } catch (t: Throwable) {
            false
        } finally {
            process?.destroy()
        }
    }

    fun isEmulator(): Boolean {
        return (Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86"))
    }
}
```

---

## 19. Jetpack Compose Specifics

### Composable Best Practices

```kotlin
// Stateless composable
@Composable
fun LoginButton(
    onClick: () -> Unit,
    enabled: Boolean,
    modifier: Modifier = Modifier
) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.fillMaxWidth()
    ) {
        Text("Login")
    }
}

// Stateful composable
@Composable
fun LoginForm(
    onLoginSuccess: () -> Unit,
    modifier: Modifier = Modifier
) {
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    val isFormValid by remember {
        derivedStateOf { email.isNotEmpty() && password.length >= 8 }
    }

    Column(modifier = modifier) {
        OutlinedTextField(
            value = email,
            onValueChange = { email = it },
            label = { Text("Email") }
        )
        
        OutlinedTextField(
            value = password,
            onValueChange = { password = it },
            label = { Text("Password") },
            visualTransformation = PasswordVisualTransformation()
        )

        LoginButton(
            onClick = { /* handle login */ },
            enabled = isFormValid
        )
    }
}
```

### Side Effects

```kotlin
@Composable
fun EmailVerificationScreen(
    token: String,
    viewModel: EmailVerificationViewModel = hiltViewModel()
) {
    // LaunchedEffect: Run suspend functions
    LaunchedEffect(token) {
        viewModel.verifyEmail(token)
    }

    // DisposableEffect: Cleanup when composable leaves composition
    DisposableEffect(Unit) {
        val listener = viewModel.addListener()
        onDispose {
            viewModel.removeListener(listener)
        }
    }

    // SideEffect: Sync Compose state to non-Compose code
    SideEffect {
        // Analytics tracking
        Analytics.logScreenView("email_verification")
    }
}
```

### Navigation with Type Safety

```kotlin
sealed class Screen(val route: String) {
    object Welcome : Screen("welcome")
    object Login : Screen("login")
    object Register : Screen("register")
    data class EmailVerification(val token: String) : Screen("verify-email/$token") {
        companion object {
            const val ROUTE = "verify-email/{token}"
        }
    }
}

@Composable
fun SumaNavGraph(navController: NavHostController) {
    NavHost(navController, startDestination = Screen.Welcome.route) {
        composable(Screen.Welcome.route) {
            WelcomeScreen(
                onLoginClick = { navController.navigate(Screen.Login.route) },
                onRegisterClick = { navController.navigate(Screen.Register.route) }
            )
        }
        
        composable(Screen.Login.route) {
            LoginScreen(navController)
        }
        
        composable(
            route = Screen.EmailVerification.ROUTE,
            arguments = listOf(navArgument("token") { type = NavType.StringType })
        ) { backStackEntry ->
            val token = backStackEntry.arguments?.getString("token") ?: ""
            EmailVerificationScreen(token)
        }
    }
}
```

---

## 20. Kotlin Coroutines & Flow

### Coroutine Scopes

```kotlin
@HiltViewModel
class AuthViewModel @Inject constructor(
    private val authRepository: AuthRepository
) : ViewModel() {

    // ViewModelScope - cancelled when ViewModel is cleared
    fun login(email: String, password: String) {
        viewModelScope.launch {
            authRepository.login(email, password)
        }
    }

    // Using different dispatchers
    fun processData() {
        viewModelScope.launch {
            // Main dispatcher (UI thread)
            showLoading()
            
            // Switch to IO dispatcher for network/database
            val result = withContext(Dispatchers.IO) {
                authRepository.fetchUserData()
            }
            
            // Back to Main dispatcher
            displayResult(result)
        }
    }

    // Error handling
    fun loginWithErrorHandling(email: String, password: String) {
        viewModelScope.launch {
            try {
                val result = authRepository.login(email, password)
                handleSuccess(result)
            } catch (e: NetworkException) {
                handleNetworkError(e)
            } catch (e: Exception) {
                handleGenericError(e)
            }
        }
    }
}
```

### Flow Operators

```kotlin
@Singleton
class AuthRepository @Inject constructor(
    private val authApi: AuthApi,
    private val secureStorage: SecureStorage
) {
    // StateFlow - hot flow with initial value
    private val _authState = MutableStateFlow<AuthState>(AuthState.Unauthenticated)
    val authState: StateFlow<AuthState> = _authState.asStateFlow()

    // Cold flow from API
    fun getUser(userId: String): Flow<User> = flow {
        val user = authApi.getUser(userId)
        emit(user)
    }.flowOn(Dispatchers.IO)

    // Flow operators
    fun observeAuthStatus(): Flow<Boolean> {
        return authState
            .map { it is AuthState.Authenticated }
            .distinctUntilChanged()
            .onEach { isAuthenticated ->
                Log.d("Auth", "Authentication status: $isAuthenticated")
            }
    }

    // Combining flows
    fun observeUserProfile(): Flow<UserProfile> {
        return combine(
            authState,
            getUserPreferences(),
            getUserSettings()
        ) { auth, preferences, settings ->
            UserProfile(auth, preferences, settings)
        }
    }

    // Error handling with catch
    fun loginFlow(email: String, password: String): Flow<Result<AuthToken>> = flow {
        val response = authApi.login(LoginRequest(email, password))
        emit(Result.success(response))
    }.catch { exception ->
        emit(Result.failure(exception))
    }.flowOn(Dispatchers.IO)
}
```

### Collecting Flows in Compose

```kotlin
@Composable
fun ProfileScreen(
    viewModel: ProfileViewModel = hiltViewModel()
) {
    // collectAsStateWithLifecycle - lifecycle-aware collection
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()

    // Collecting side effects
    val context = LocalContext.current
    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is ProfileEvent.ShowToast -> {
                    Toast.makeText(context, event.message, Toast.LENGTH_SHORT).show()
                }
                is ProfileEvent.NavigateBack -> {
                    // Handle navigation
                }
            }
        }
    }

    ProfileContent(uiState)
}
```

---

## Summary

This Android Mobile Specification document provides a comprehensive blueprint for implementing user registration and authentication features in SUMA Finance using:

- **100% Jetpack Compose** UI framework with Material Design 3
- **Clean Architecture + MVVM** pattern with multi-module structure
- **Hilt** for dependency injection
- **Kotlin Coroutines & Flow** for asynchronous operations
- **Retrofit + OkHttp** for networking with SSL pinning
- **EncryptedSharedPreferences** for secure token storage
- **Biometric authentication** for enhanced security
- **Firebase Cloud Messaging** for push notifications
- **WorkManager** for background token refresh
- **Comprehensive testing** strategy with JUnit, MockK, and Compose tests

All implementations follow Android best practices, Material Design guidelines, and financial app security requirements. The architecture is scalable, maintainable, and ready for production deployment on the Google Play Store.

---

**Next Steps:**
1. Review and approve this specification
2. Set up project structure and dependencies
3. Implement authentication feature module
4. Conduct code reviews and testing
5. Prepare for Play Store submission