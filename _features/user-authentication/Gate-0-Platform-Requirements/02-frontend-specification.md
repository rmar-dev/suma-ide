---
layout: default
title: 02 Frontend Specification
nav_exclude: true
---


# Frontend Specification: Authentication System

## 1. Frontend Architecture Overview

**Framework**: React 18+ with TypeScript

**State Management**: 
- Zustand for global auth state (lightweight, ~1KB)
- React Query (TanStack Query) for server state and API caching
- Context API for theme/locale preferences

**Routing Strategy**:
- React Router v6 with protected route wrapper
- Code splitting per route for optimal bundle size
- Persistent routing state during token refresh

**Build Tooling**:
- Vite for development and production builds
- SWC for fast TypeScript compilation
- Rollup for optimized bundle generation

---

## 2. Component Architecture

### Core Authentication Components

#### Component: `LoginForm`
```typescript
Props:
- onSuccess: () => void
- redirectPath?: string
- allowSocialLogin?: boolean

State:
- email: string
- password: string
- rememberMe: boolean
- showPassword: boolean
- isSubmitting: boolean
- errorMessage: string | null
- rateLimitRemaining: number

Events:
- onSubmit: Validate and submit credentials
- onForgotPassword: Navigate to /auth/reset-password
- onSocialLogin: Trigger OAuth flow
- onTogglePassword: Show/hide password
```

#### Component: `RegistrationForm`
```typescript
Props:
- onSuccess: (userId: string) => void
- requireEmailVerification: boolean

State:
- email: string
- password: string
- passwordConfirm: string
- consents: { terms: boolean, privacy: boolean, marketing: boolean }
- passwordStrength: { score: number, feedback: string[] }
- isSubmitting: boolean
- errors: Record<string, string>

Events:
- onSubmit: Create account with consent tracking
- onPasswordChange: Real-time strength validation
- onCheckBreachedPassword: Check HaveIBeenPwned API
```

#### Component: `TwoFactorPrompt`
```typescript
Props:
- userId: string
- onSuccess: () => void
- onCancel: () => void
- method: 'email' | 'totp'

State:
- otpCode: string (6 digits)
- isVerifying: boolean
- attemptsRemaining: number
- canResend: boolean
- resendCountdown: number

Events:
- onVerifyOTP: Submit OTP code
- onResendOTP: Request new OTP (rate limited)
- onUseBackupCode: Switch to backup code input
```

#### Component: `PasswordResetFlow`
```typescript
Props:
- token?: string (from URL)

State:
- step: 'request' | 'verify_email' | 'new_password'
- email: string
- newPassword: string
- resetToken: string
- isSubmitting: boolean

Events:
- onRequestReset: Send reset email
- onVerifyToken: Validate token from email link
- onSetNewPassword: Submit new password
```

#### Component: `EmailVerificationBanner`
```typescript
Props:
- email: string
- onResend: () => Promise<void>
- onDismiss: () => void

State:
- canResend: boolean
- countdown: number
- isResending: boolean
```

#### Component: `DeviceManager`
```typescript
Props:
- userId: string

State:
- devices: Device[]
- isLoading: boolean

Events:
- onRevokeDevice: Revoke refresh token for device
- onTrustDevice: Mark current device as trusted
```

#### Component: `ConsentManager`
```typescript
Props:
- consents: Consent[]
- onChange: (consents: Consent[]) => void

State:
- selections: Record<string, boolean>

Events:
- onToggleConsent: Update consent selection
- onViewDetails: Show consent details modal
```

---

## 3. Page Structure & Routing

### Route Definitions

```typescript
/auth/login          → LoginPage
/auth/register       → RegistrationPage
/auth/verify-email   → EmailVerificationPage (token param)
/auth/reset-password → PasswordResetPage (token param)
/auth/2fa-setup      → TwoFactorSetupPage (protected)
/auth/devices        → DeviceManagementPage (protected)

/dashboard           → DashboardPage (protected)
/settings/security   → SecuritySettingsPage (protected)
/settings/privacy    → PrivacySettingsPage (protected)
```

### Protected Routes

```typescript
<Route element={<ProtectedRoute requiredAuth={true} />}>
  <Route path="/dashboard" element={<Dashboard />} />
  <Route path="/settings/*" element={<Settings />} />
</Route>

// ProtectedRoute logic:
// - Check access token validity
// - Attempt refresh if expired
// - Redirect to /auth/login if refresh fails
// - Store intended destination for post-login redirect
```

### Navigation Flow

```
Landing → Login → [2FA Prompt] → Dashboard
          ↓
      Registration → Email Verification → Login
          
Login → Forgot Password → Email Sent → Reset Password → Login

Dashboard → Settings → Security → Enable 2FA → 2FA Setup
```

### Deep Linking

- Email verification: `app://auth/verify-email?token=xxx`
- Password reset: `app://auth/reset-password?token=xxx`
- Social login callbacks: `app://auth/callback/google?code=xxx`

---

## 4. State Management

### Global Auth State (Zustand)

```typescript
interface AuthState {
  user: User | null
  accessToken: string | null
  isAuthenticated: boolean
  isEmailVerified: boolean
  mfaEnabled: boolean
  
  // Actions
  login: (credentials: Credentials) => Promise<void>
  logout: () => Promise<void>
  refreshToken: () => Promise<void>
  updateUser: (user: Partial<User>) => void
  clearAuth: () => void
}
```

### Server State (React Query)

```typescript
// Queries
useUser()           // Current user details
useDevices()        // Active devices
useConsents()       // User consent records
useAuthEvents()     // Recent auth events

// Mutations
useLogin()          // Login mutation
useRegister()       // Registration mutation
useVerifyEmail()    // Email verification
useResetPassword()  // Password reset
useEnableMFA()      // Enable 2FA
```

### State Persistence

- **Access Token**: Memory only (Zustand store)
- **Refresh Token**: httpOnly secure cookie
- **User Preferences**: localStorage (theme, language)
- **Device Trust**: localStorage (device fingerprint)

### State Synchronization

- React Query automatic refetch on window focus
- WebSocket connection for real-time session revocation
- Polling for auth events every 60 seconds when active

---

## 5. API Integration

### API Client Setup

```typescript
// Axios instance with interceptors
const apiClient = axios.create({
  baseURL: process.env.VITE_API_BASE_URL,
  timeout: 10000,
  withCredentials: true, // Send httpOnly cookies
})

// Request interceptor: Add access token
apiClient.interceptors.request.use((config) => {
  const token = authStore.getState().accessToken
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// Response interceptor: Handle 401 and refresh
apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      try {
        await authStore.getState().refreshToken()
        return apiClient.request(error.config)
      } catch {
        authStore.getState().clearAuth()
        window.location.href = '/auth/login'
      }
    }
    return Promise.reject(error)
  }
)
```

### Error Handling

```typescript
// Standardized error responses
interface APIError {
  code: string
  message: string
  details?: Record<string, string[]>
}

// Error mapping
const errorMessages = {
  AUTH_INVALID_CREDENTIALS: 'Invalid email or password',
  AUTH_ACCOUNT_LOCKED: 'Account locked due to multiple failed attempts',
  AUTH_EMAIL_NOT_VERIFIED: 'Please verify your email before logging in',
  AUTH_MFA_REQUIRED: 'Two-factor authentication required',
  RATE_LIMIT_EXCEEDED: 'Too many requests. Please try again later',
}
```

### Loading States

```typescript
// Per-request loading with React Query
const { data, isLoading, isError, error } = useLogin()

// Global loading overlay for critical operations
const [globalLoading, setGlobalLoading] = useState(false)
```

### Optimistic Updates

```typescript
// Update UI immediately, rollback on error
const updateConsentMutation = useMutation({
  mutationFn: updateConsent,
  onMutate: async (newConsent) => {
    await queryClient.cancelQueries(['consents'])
    const previous = queryClient.getQueryData(['consents'])
    queryClient.setQueryData(['consents'], (old) => [...old, newConsent])
    return { previous }
  },
  onError: (err, variables, context) => {
    queryClient.setQueryData(['consents'], context.previous)
  },
})
```

---

## 6. Authentication Flow

### Login Flow

1. User submits email + password
2. Frontend validates format
3. POST `/api/auth/login` with credentials
4. Backend returns:
   - If MFA disabled: `{ accessToken, user }`
   - If MFA enabled: `{ requiresMFA: true, userId }`
5. If MFA required → Show `TwoFactorPrompt`
6. Submit OTP → POST `/api/auth/verify-mfa`
7. Receive access token, store in memory
8. Redirect to intended destination

### Token Storage

- **Access Token**: Zustand store (memory only)
  - Expires in 15 minutes
  - Never persisted to localStorage/sessionStorage
- **Refresh Token**: httpOnly secure cookie
  - Expires in 7 days
  - SameSite=Strict
  - Secure flag in production

### Token Refresh Mechanism

```typescript
// Automatic refresh 1 minute before expiry
useEffect(() => {
  const token = authStore.getState().accessToken
  if (!token) return

  const decoded = jwtDecode(token)
  const expiresIn = decoded.exp * 1000 - Date.now()
  const refreshAt = expiresIn - 60000 // 1 min before

  const timer = setTimeout(() => {
    authStore.getState().refreshToken()
  }, refreshAt)

  return () => clearTimeout(timer)
}, [authStore.getState().accessToken])

// Refresh token endpoint
POST /api/auth/refresh
// Uses httpOnly cookie, returns new access token
```

### Session Management

- Concurrent sessions allowed (max 5 devices)
- Device tracking via User-Agent + device fingerprint
- Session revocation via device management UI
- Real-time session invalidation via WebSocket

### Logout Flow

1. POST `/api/auth/logout` (revokes refresh token)
2. Clear Zustand state
3. Clear React Query cache
4. Redirect to `/auth/login`

---

## 7. Forms & Validation

### Form Library

**React Hook Form** with Zod schema validation

```typescript
const loginSchema = z.object({
  email: z.string().email('Invalid email address'),
  password: z.string().min(1, 'Password is required'),
})

const { register, handleSubmit, formState: { errors } } = useForm({
  resolver: zodResolver(loginSchema),
})
```

### Validation Strategy

**Client-Side (Immediate)**:
- Email format validation
- Password length (12-128 chars)
- Required field checks

**Server-Side (On Submit)**:
- Email existence check
- Password complexity (uppercase, lowercase, number, special char)
- Compromised password check (HaveIBeenPwned)
- Rate limiting enforcement

### Real-Time Password Strength

```typescript
// Password strength meter (zxcvbn library)
const strength = zxcvbn(password)
// Score: 0-4 (weak to strong)
// Feedback: Array of improvement suggestions

// Visual indicator: progress bar + color coding
// Red (0-1), Orange (2), Yellow (3), Green (4)
```

### Error Display

```typescript
// Field-level errors (below input)
{errors.email && (
  <span role="alert" className="error">
    {errors.email.message}
  </span>
)}

// Form-level errors (top of form)
{apiError && (
  <div role="alert" aria-live="assertive" className="alert-error">
    {apiError}
  </div>
)}
```

### Accessibility

- Proper `<label>` associations with `htmlFor`
- ARIA labels for icon buttons
- Error messages linked with `aria-describedby`
- Focus management (error → first invalid field)
- Screen reader announcements for async validation

---

## 8. UI/UX Design System

### Component Library

**Custom components** built with:
- Radix UI primitives (headless components)
- Tailwind CSS for styling
- Framer Motion for animations

**Rationale**: Full control over auth UX, minimal bundle size

### Theme Configuration

```typescript
const theme = {
  colors: {
    primary: { 500: '#3B82F6', 600: '#2563EB' },
    success: { 500: '#10B981' },
    error: { 500: '#EF4444' },
    warning: { 500: '#F59E0B' },
  },
  typography: {
    fontFamily: 'Inter, system-ui, sans-serif',
    fontSize: { base: '16px', sm: '14px', lg: '18px' },
  },
  spacing: { xs: '4px', sm: '8px', md: '16px', lg: '24px', xl: '32px' },
}
```

### Responsive Design Breakpoints

```css
/* Mobile first approach */
sm: 640px   /* Large phones */
md: 768px   /* Tablets */
lg: 1024px  /* Laptops */
xl: 1280px  /* Desktops */
```

### Accessibility Standards

**WCAG 2.1 AA Compliance**:
- Color contrast ratio ≥ 4.5:1 (text)
- Color contrast ratio ≥ 3:1 (UI components)
- Keyboard navigation (Tab, Enter, Escape)
- Focus indicators (2px solid outline)
- Screen reader support (ARIA labels, roles, live regions)
- Form error announcements
- Skip links for main content

**Testing Tools**:
- axe DevTools browser extension
- Pa11y automated testing
- Manual screen reader testing (NVDA, JAWS)

### Browser/Device Compatibility

**Desktop**:
- Chrome 120+ (latest 2 versions)
- Firefox 121+ (latest 2 versions)
- Safari 17+ (latest 2 versions)
- Edge 120+ (latest 2 versions)

**Mobile**:
- iOS Safari 16.4+ (latest 2 versions)
- Chrome Android 120+ (latest 2 versions)

**Minimum Supported**:
- Chrome 119, Firefox 120, Safari 16.3, Edge 119
- iOS Safari 16.3, Chrome Android 119

**Graceful Degradation**:
- Biometric auth → Fallback to password
- WebAuthn → Fallback to email OTP
- WebSocket → Fallback to polling
- Modern CSS → Fallback layouts for older browsers

### Internationalization (i18n)

**Languages Supported**: Portuguese (pt-PT), English (en-US)

**Translation Strategy**: react-i18next

```typescript
import i18n from 'i18next'
import { initReactI18next } from 'react-i18next'

i18n.use(initReactI18next).init({
  resources: {
    en: { translation: enTranslations },
    pt: { translation: ptTranslations },
  },
  lng: 'pt', // Default Portuguese
  fallbackLng: 'en',
  interpolation: { escapeValue: false },
})
```

**Locale-Specific Formatting**:
- Dates: `Intl.DateTimeFormat(locale)` (pt-PT: dd/mm/yyyy, en-US: mm/dd/yyyy)
- Numbers: `Intl.NumberFormat(locale)`
- Currency: EUR for pt-PT, USD for en-US

**Language Switcher UI**:
- Dropdown in header/footer
- Persisted to localStorage (`preferredLanguage`)
- URL param support (`?lang=pt`)

**RTL Support**: Not required (Portuguese and English are LTR)

---

## 9. Security Implementation

### XSS Prevention

- React automatic escaping for JSX
- DOMPurify for user-generated HTML (if any)
- Content Security Policy enforcement
- No `dangerouslySetInnerHTML` usage
- Sanitize error messages from API

### CSRF Protection

- Double-submit cookie pattern
- Backend generates CSRF token on page load
- Frontend includes `X-CSRF-Token` header in all mutations
- SameSite=Strict cookies

### Content Security Policy

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self' 'wasm-unsafe-eval';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  connect-src 'self' https://api.finance-app.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
```

### Secure Cookie Handling

```http
Set-Cookie: refreshToken=xxx;
  HttpOnly;
  Secure;
  SameSite=Strict;
  Max-Age=604800;
  Path=/api/auth;
```

### Input Sanitization

```typescript
// Trim whitespace
const sanitizeEmail = (email: string) => email.trim().toLowerCase()

// Remove non-alphanumeric (except allowed chars)
const sanitizeName = (name: string) => 
  name.replace(/[^a-zA-Z0-9\s\-']/g, '')

// Validate before sending to API
```

### Security Headers (Expected from Backend)

```http
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

---

## 10. Performance Optimization

### Performance Targets

- **First Contentful Paint**: < 1.5s
- **Time to Interactive**: < 3s
- **Lighthouse Performance Score**: > 90
- **Bundle Size**: < 200KB gzipped (initial load)
- **Login Response Time**: < 200ms

### Code Splitting Strategy

```typescript
// Route-based splitting
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Settings = lazy(() => import('./pages/Settings'))

// Component-based splitting (heavy components)
const DeviceManager = lazy(() => import('./components/DeviceManager'))
```

### Lazy Loading

- Auth pages loaded on-demand
- Heavy libraries (zxcvbn, qrcode) loaded only when needed
- Images with `loading="lazy"`

### Image Optimization

- WebP format with PNG fallback
- Responsive images with `srcset`
- SVG for icons (inlined)
- CDN delivery for static assets

### Caching Strategy

**React Query Cache**:
- User data: 5 minutes stale time
- Consent records: 10 minutes
- Device list: 1 minute

**HTTP Caching**:
- Static assets: 1 year (`Cache-Control: public, max-age=31536000, immutable`)
- API responses: No cache (`Cache-Control: no-store`)

### Bundle Size Optimization

- Tree shaking enabled (ES modules)
- Dynamic imports for heavy libraries
- Lodash imports via `lodash-es` (tree-shakeable)
- Remove unused dependencies
- Vite bundle analyzer to track size

**Target Breakdown**:
- Vendor bundle: < 120KB gzipped
- App bundle: < 80KB gzipped
- Total initial load: < 200KB gzipped

---

## 11. Testing Strategy

### Unit Testing

**Framework**: Vitest (fast, Vite-native)

**Coverage Target**: > 80%

**Tests**:
- Form validation logic
- Password strength calculation
- Token expiration checks
- Utility functions (sanitization, formatting)
- Zustand store actions

```typescript
// Example: Password validation
test('validates password complexity', () => {
  expect(validatePassword('weak')).toBe(false)
  expect(validatePassword('Strong123!')).toBe(true)
})
```

### Component Testing

**Framework**: React Testing Library

**Tests**:
- `LoginForm`: Submit with valid/invalid data
- `RegistrationForm`: Consent tracking, password strength
- `TwoFactorPrompt`: OTP validation, resend logic
- `PasswordResetFlow`: Multi-step flow navigation

```typescript
// Example: LoginForm submission
test('displays error on invalid credentials', async () => {
  render(<LoginForm />)
  
  fireEvent.change(screen.getByLabelText(/email/i), {
    target: { value: 'test@example.com' },
  })
  fireEvent.change(screen.getByLabelText(/password/i), {
    target: { value: 'wrongpassword' },
  })
  fireEvent.click(screen.getByRole('button', { name: /log in/i }))
  
  await waitFor(() => {
    expect(screen.getByText(/invalid email or password/i)).toBeInTheDocument()
  })
})
```

### E2E Testing

**Framework**: Playwright

**Critical Flows**:
1. **Registration Flow**: Fill form → Receive email → Verify → Login
2. **Login Flow**: Valid credentials → Dashboard
3. **Password Reset Flow**: Request reset → Receive email → Set new password → Login
4. **2FA Setup**: Navigate to settings → Enable 2FA → Verify OTP
5. **Session Revocation**: Login on two devices → Revoke one → Verify logout

```typescript
// Example: Registration E2E
test('complete registration flow', async ({ page }) => {
  await page.goto('/auth/register')
  
  await page.fill('[name="email"]', 'newuser@example.com')
  await page.fill('[name="password"]', 'StrongPass123!')
  await page.check('[name="consents.terms"]')
  await page.check('[name="consents.privacy"]')
  await page.click('button[type="submit"]')
  
  await expect(page).toHaveURL('/auth/verify-email')
  
  // Simulate email click (in test env)
  const verificationUrl = await getVerificationUrl('newuser@example.com')
  await page.goto(verificationUrl)
  
  await expect(page).toHaveURL('/auth/login')
})
```

### Accessibility Testing

**Tools**:
- Jest-axe for automated checks
- Manual keyboard navigation testing
- Screen reader testing (NVDA on Windows, VoiceOver on macOS)

```typescript
import { axe, toHaveNoViolations } from 'jest-axe'

test('LoginForm has no accessibility violations', async () => {
  const { container } = render(<LoginForm />)
  const results = await axe(container)
  expect(results).toHaveNoViolations()
})
```

### Security Testing

- CSP violations monitoring in tests
- XSS payload injection tests (sanitization)
- Token expiration and refresh logic
- Logout invalidation verification

---

## 12. Build & Deployment

### Build Optimization

**Vite Configuration**:
```typescript
export default defineConfig({
  build: {
    target: 'es2020',
    minify: 'terser',
    sourcemap: false,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'auth': ['zustand', '@tanstack/react-query'],
        },
      },
    },
  },
  esbuild: {
    drop: ['console', 'debugger'], // Remove in production
  },
})
```

### Environment Configuration

```typescript
// .env.development
VITE_API_BASE_URL=http://localhost:8080/api
VITE_ENVIRONMENT=development

// .env.production
VITE_API_BASE_URL=https://api.finance-app.com/api
VITE_ENVIRONMENT=production
```

**Runtime Config Validation** (with Zod):
```typescript
const envSchema = z.object({
  VITE_API_BASE_URL: z.string().url(),
  VITE_ENVIRONMENT: z.enum(['development', 'staging', 'production']),
})

const env = envSchema.parse(import.meta.env)
```

### CDN Strategy

- **Static Assets**: CloudFront CDN
  - JS bundles: `/assets/*.js`
  - CSS: `/assets/*.css`
  - Images: `/images/*`
- **Cache Invalidation**: Versioned filenames (`app.abc123.js`)
- **Fallback**: Origin server if CDN unavailable

### Progressive Web App (PWA) Features

**Service Worker** (Workbox):
- Cache static assets (app shell)
- Offline fallback page
- Network-first strategy for API calls

**Manifest**:
```json
{
  "name": "Finance App",
  "short_name": "Finance",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#ffffff",
  "theme_color": "#3B82F6",
  "icons": [
    { "src": "/icons/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icons/icon-512.png", "sizes": "512x512", "type": "image/png" }
  ]
}
```

**Offline Support**:
- Cached login page
- "You're offline" message
- Queue auth requests when connection restored

### Deployment Pipeline

1. **Build**: `npm run build` (generates `/dist`)
2. **Bundle Analysis**: Check bundle sizes vs. targets
3. **Upload to S3**: Sync `/dist` to S3 bucket
4. **Invalidate CDN**: CloudFront cache invalidation for `/*.html`
5. **Smoke Tests**: Run critical E2E tests against production URL
6. **Monitoring**: Alert on error rate spikes (Sentry)

**Rollback Strategy**: Keep previous 5 builds, instant rollback via S3 versioning + CDN invalidation

---

**End of Frontend Specification**
