


```markdown
# Frontend Architecture - User Registration & Authentication

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Frontend Architecture
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Architecture Overview

### 1.1 Frontend Technology Stack
- **Framework**: React 18+ with TypeScript
- **State Management**: Redux Toolkit + RTK Query
- **Routing**: React Router v6
- **Form Management**: React Hook Form + Zod validation
- **UI Components**: Custom component library with accessibility (WCAG 2.1 AA)
- **Styling**: CSS Modules + Tailwind CSS
- **Testing**: Vitest + React Testing Library + Playwright
- **Build Tool**: Vite
- **Package Manager**: npm/pnpm

### 1.2 Architecture Patterns
- **Component Architecture**: Atomic Design (Atoms → Molecules → Organisms → Templates → Pages)
- **State Management Pattern**: Redux Toolkit with feature-based slices
- **API Communication**: RTK Query for caching and optimistic updates
- **Authentication Flow**: Token-based with automatic refresh
- **Error Handling**: Centralized error boundary with user-friendly messages
- **Code Splitting**: Route-based lazy loading
- **Security Pattern**: Defense in depth with client-side validation + server verification

### 1.3 Module Structure
```
src/
├── features/
│   └── auth/
│       ├── components/          # Feature-specific components
│       ├── hooks/               # Custom hooks
│       ├── store/               # Redux slices
│       ├── api/                 # RTK Query endpoints
│       ├── utils/               # Helper functions
│       ├── types/               # TypeScript interfaces
│       └── __tests__/           # Feature tests
├── shared/
│   ├── components/              # Reusable UI components
│   ├── hooks/                   # Shared hooks
│   ├── utils/                   # Utility functions
│   ├── constants/               # App constants
│   └── types/                   # Shared types
├── layouts/                     # Page layouts
├── pages/                       # Route pages
├── store/                       # Global Redux store
├── services/                    # API services
└── styles/                      # Global styles
```

---

## 2. Component Architecture

### 2.1 Authentication Components Hierarchy

#### **Pages (Routes)**
- `LoginPage` - `/login`
- `RegisterPage` - `/register`
- `VerifyEmailPage` - `/verify-email/:token`
- `ForgotPasswordPage` - `/forgot-password`
- `ResetPasswordPage` - `/reset-password/:token`
- `TwoFactorAuthPage` - `/2fa`
- `AccountSettingsPage` - `/settings/account`

#### **Organisms**
- `LoginForm` - Complete login form with email/password + 2FA
- `RegistrationForm` - Multi-step registration wizard
- `PasswordResetForm` - Password reset request form
- `NewPasswordForm` - Set new password after reset
- `TwoFactorSetupWizard` - 2FA enrollment flow
- `GDPRConsentManager` - Granular consent collection
- `DeviceManagementPanel` - Trusted devices list
- `SessionManagementPanel` - Active sessions control

#### **Molecules**
- `EmailPasswordInput` - Email + password field group
- `PasswordStrengthIndicator` - Real-time password strength meter
- `OTPInput` - 6-digit OTP entry component
- `ConsentCheckbox` - GDPR consent checkbox with modal
- `SocialLoginButtons` - Google/Apple Sign-In buttons
- `SecurityAlertBanner` - Display security warnings
- `SessionCard` - Individual session information card

#### **Atoms**
- `Input` - Accessible form input with validation
- `Button` - Primary/secondary/tertiary buttons
- `Checkbox` - Accessible checkbox component
- `Link` - Styled navigation link
- `Label` - Form label component
- `ErrorMessage` - Validation error display
- `LoadingSpinner` - Loading indicator
- `Icon` - SVG icon wrapper

### 2.2 Key Component Specifications

#### **RegistrationForm Component**
```typescript
interface RegistrationFormProps {
  onSuccess?: (user: User) => void;
  onError?: (error: Error) => void;
  redirectPath?: string;
}

interface RegistrationFormData {
  email: string;
  password: string;
  confirmPassword: string;
  firstName: string;
  lastName: string;
  gdprConsent: boolean;
  marketingConsent: boolean;
  termsAccepted: boolean;
}

// Steps
// 1. Personal Information (email, name)
// 2. Password Creation (with strength indicator)
// 3. GDPR Consents (required + optional)
// 4. Email Verification (OTP sent)
```

#### **LoginForm Component**
```typescript
interface LoginFormProps {
  onSuccess?: (tokens: AuthTokens) => void;
  onTwoFactorRequired?: (sessionId: string) => void;
  redirectPath?: string;
}

interface LoginFormData {
  email: string;
  password: string;
  rememberMe: boolean;
}

// Features
// - Email/password validation
// - Account lockout messaging
// - "Forgot Password" link
// - Social login options
// - Device trust option
```

#### **TwoFactorAuthPage Component**
```typescript
interface TwoFactorAuthProps {
  sessionId: string;
  email: string;
  onSuccess?: () => void;
}

// Features
// - 6-digit OTP input
// - Resend OTP (60s cooldown)
// - OTP expiry countdown (5 min)
// - Backup code option
// - Cancel/logout option
```

---

## 3. State Management

### 3.1 Redux Store Structure
```typescript
{
  auth: {
    user: User | null;
    tokens: AuthTokens | null;
    isAuthenticated: boolean;
    isLoading: boolean;
    error: string | null;
    sessionId: string | null;
    requiresTwoFactor: boolean;
  },
  consent: {
    gdprConsent: ConsentRecord[];
    lastUpdated: string;
  },
  security: {
    devices: TrustedDevice[];
    sessions: ActiveSession[];
    securityEvents: SecurityEvent[];
  }
}
```

### 3.2 Redux Slices

#### **authSlice**
```typescript
// Actions
- login({ email, password, rememberMe })
- logout()
- register({ email, password, firstName, lastName, consents })
- verifyEmail({ token })
- refreshToken()
- resetPassword({ email })
- setNewPassword({ token, newPassword })
- verifyOTP({ sessionId, otp })
- resendOTP({ sessionId })

// Selectors
- selectUser
- selectIsAuthenticated
- selectAuthError
- selectRequiresTwoFactor
```

#### **consentSlice**
```typescript
// Actions
- updateConsent({ type, granted, timestamp })
- withdrawConsent({ type })
- fetchConsentHistory()

// Selectors
- selectGDPRConsent
- selectMarketingConsent
- selectConsentHistory
```

### 3.3 RTK Query API Endpoints
```typescript
// authApi
- login(credentials)
- register(userData)
- logout()
- refreshToken()
- verifyEmail(token)
- requestPasswordReset(email)
- resetPassword({ token, newPassword })
- verifyOTP({ sessionId, otp })
- resendOTP(sessionId)
- getCurrentUser()
- updateProfile(data)

// securityApi
- getTrustedDevices()
- addTrustedDevice(device)
- removeTrustedDevice(deviceId)
- getActiveSessions()
- terminateSession(sessionId)
- getSecurityEvents({ page, limit })
```

---

## 4. Routing & Navigation

### 4.1 Route Configuration
```typescript
// Public Routes
/login
/register
/forgot-password
/reset-password/:token
/verify-email/:token

// Protected Routes (require authentication)
/dashboard
/settings/account
/settings/security
/settings/privacy

// Semi-Protected Routes (require session but not full auth)
/2fa
```

### 4.2 Route Guards
```typescript
// ProtectedRoute Component
- Checks isAuthenticated
- Redirects to /login if not authenticated
- Stores intended destination for post-login redirect

// PublicOnlyRoute Component
- Redirects to /dashboard if already authenticated
- Used for login/register pages

// TwoFactorGuard Component
- Allows access only if requiresTwoFactor is true
- Redirects to /login if session expired
```

### 4.3 Navigation Flow
```
1. User Registration Flow
   /register → email verification → /verify-email/:token → /dashboard

2. Login Flow (No 2FA)
   /login → /dashboard

3. Login Flow (With 2FA)
   /login → /2fa → /dashboard

4. Password Reset Flow
   /forgot-password → email sent → /reset-password/:token → /login
```

---

## 5. Form Management & Validation

### 5.1 React Hook Form + Zod Schema

#### **Registration Validation**
```typescript
const registrationSchema = z.object({
  email: z.string()
    .email('Invalid email format')
    .max(254, 'Email too long'),
  password: z.string()
    .min(12, 'Password must be at least 12 characters')
    .regex(/[A-Z]/, 'Must contain uppercase letter')
    .regex(/[a-z]/, 'Must contain lowercase letter')
    .regex(/[0-9]/, 'Must contain number')
    .regex(/[^A-Za-z0-9]/, 'Must contain special character'),
  confirmPassword: z.string(),
  firstName: z.string()
    .min(1, 'First name required')
    .max(50, 'First name too long'),
  lastName: z.string()
    .min(1, 'Last name required')
    .max(50, 'Last name too long'),
  gdprConsent: z.boolean()
    .refine(val => val === true, 'GDPR consent required'),
  marketingConsent: z.boolean(),
  termsAccepted: z.boolean()
    .refine(val => val === true, 'Must accept terms')
}).refine(data => data.password === data.confirmPassword, {
  message: 'Passwords must match',
  path: ['confirmPassword']
});
```

#### **Login Validation**
```typescript
const loginSchema = z.object({
  email: z.string().email('Invalid email'),
  password: z.string().min(1, 'Password required'),
  rememberMe: z.boolean().optional()
});
```

### 5.2 Client-Side Validation Rules
- **Email**: RFC 5322 format validation
- **Password**: Complexity enforced (see security requirements)
- **Name Fields**: No special characters except hyphen/apostrophe
- **OTP**: 6 digits only, no spaces
- **Real-time Validation**: On blur and on submit
- **Error Display**: Below field with ARIA live region

---

## 6. Security Implementation

### 6.1 Token Management
```typescript
// Token Storage
- Access Token: Memory only (Redux store, cleared on refresh)
- Refresh Token: HttpOnly cookie (secure, SameSite=Strict)
- CSRF Token: Session storage

// Token Refresh Strategy
- Auto-refresh on 401 response
- Proactive refresh at 80% of token lifetime
- Queue failed requests during refresh
- Logout on refresh failure

// Implementation
class TokenManager {
  private refreshPromise: Promise<void> | null = null;
  
  async refreshToken(): Promise<void> {
    if (this.refreshPromise) return this.refreshPromise;
    
    this.refreshPromise = this.api.refreshToken()
      .then(tokens => {
        store.dispatch(setTokens(tokens));
        this.scheduleNextRefresh();
      })
      .finally(() => {
        this.refreshPromise = null;
      });
    
    return this.refreshPromise;
  }
}
```

### 6.2 Secure HTTP Client
```typescript
// Axios Interceptor Configuration
const apiClient = axios.create({
  baseURL: process.env.VITE_API_URL,
  timeout: 10000,
  withCredentials: true, // Send HttpOnly cookies
  headers: {
    'Content-Type': 'application/json',
    'X-Requested-With': 'XMLHttpRequest'
  }
});

// Request Interceptor
apiClient.interceptors.request.use(config => {
  const token = store.getState().auth.tokens?.accessToken;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  
  const csrfToken = sessionStorage.getItem('csrf_token');
  if (csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  
  return config;
});

// Response Interceptor
apiClient.interceptors.response.use(
  response => response,
  async error => {
    if (error.response?.status === 401) {
      const originalRequest = error.config;
      
      if (!originalRequest._retry) {
        originalRequest._retry = true;
        await tokenManager.refreshToken();
        return apiClient(originalRequest);
      }
      
      store.dispatch(logout());
      window.location.href = '/login';
    }
    
    return Promise.reject(error);
  }
);
```

### 6.3 XSS Prevention
- **Content Security Policy**: Enforced via meta tag
- **Input Sanitization**: DOMPurify for user-generated content
- **Output Encoding**: React automatic escaping
- **Dangerous HTML**: Avoid dangerouslySetInnerHTML
- **Event Handlers**: No inline JavaScript

### 6.4 CSRF Protection
- **Token Storage**: Session storage (not localStorage)
- **Token Transmission**: Custom header (X-CSRF-Token)
- **Token Refresh**: On login and every 30 minutes
- **SameSite Cookies**: Strict mode for refresh tokens

### 6.5 Rate Limiting (Client-Side)
```typescript
class RateLimiter {
  private attempts: Map<string, number[]> = new Map();
  
  canAttempt(action: string, maxAttempts: number, windowMs: number): boolean {
    const now = Date.now();
    const attempts = this.attempts.get(action) || [];
    const recentAttempts = attempts.filter(t => now - t < windowMs);
    
    if (recentAttempts.length >= maxAttempts) {
      return false;
    }
    
    recentAttempts.push(now);
    this.attempts.set(action, recentAttempts);
    return true;
  }
}

// Usage
if (!rateLimiter.canAttempt('login', 5, 60000)) {
  throw new Error('Too many login attempts. Please wait 1 minute.');
}
```

---

## 7. API Integration

### 7.1 RTK Query Configuration
```typescript
import { createApi, fetchBaseQuery } from '@reduxjs/toolkit/query/react';

export const authApi = createApi({
  reducerPath: 'authApi',
  baseQuery: fetchBaseQuery({
    baseUrl: '/api/v1',
    prepareHeaders: (headers, { getState }) => {
      const token = (getState() as RootState).auth.tokens?.accessToken;
      if (token) {
        headers.set('Authorization', `Bearer ${token}`);
      }
      return headers;
    },
    credentials: 'include'
  }),
  tagTypes: ['User', 'Sessions', 'Devices'],
  endpoints: (builder) => ({
    login: builder.mutation<AuthResponse, LoginRequest>({
      query: (credentials) => ({
        url: '/auth/login',
        method: 'POST',
        body: credentials
      }),
      invalidatesTags: ['User']
    }),
    register: builder.mutation<AuthResponse, RegisterRequest>({
      query: (userData) => ({
        url: '/auth/register',
        method: 'POST',
        body: userData
      })
    }),
    getCurrentUser: builder.query<User, void>({
      query: () => '/auth/me',
      providesTags: ['User']
    }),
    getActiveSessions: builder.query<Session[], void>({
      query: () => '/auth/sessions',
      providesTags: ['Sessions']
    }),
    terminateSession: builder.mutation<void, string>({
      query: (sessionId) => ({
        url: `/auth/sessions/${sessionId}`,
        method: 'DELETE'
      }),
      invalidatesTags: ['Sessions']
    })
  })
});

export const {
  useLoginMutation,
  useRegisterMutation,
  useGetCurrentUserQuery,
  useGetActiveSessionsQuery,
  useTerminateSessionMutation
} = authApi;
```

### 7.2 API Response Types
```typescript
interface AuthResponse {
  user: User;
  accessToken: string;
  requiresTwoFactor: boolean;
  sessionId?: string;
}

interface User {
  id: string;
  email: string;
  firstName: string;
  lastName: string;
  emailVerified: boolean;
  twoFactorEnabled: boolean;
  createdAt: string;
}

interface Session {
  id: string;
  deviceName: string;
  ipAddress: string;
  lastActive: string;
  isCurrent: boolean;
}

interface ApiError {
  status: number;
  message: string;
  errors?: Record<string, string[]>;
}
```

### 7.3 Error Handling
```typescript
// Centralized Error Handler
const handleApiError = (error: unknown): string => {
  if (isFetchBaseQueryError(error)) {
    if (error.status === 401) {
      return 'Authentication failed. Please check your credentials.';
    }
    if (error.status === 429) {
      return 'Too many attempts. Please try again later.';
    }
    if (error.status === 422) {
      const data = error.data as ApiError;
      return data.message || 'Validation failed';
    }
  }
  
  return 'An unexpected error occurred. Please try again.';
};

// Usage in Component
const [login, { isLoading, error }] = useLoginMutation();

const handleSubmit = async (data: LoginFormData) => {
  try {
    await login(data).unwrap();
    navigate('/dashboard');
  } catch (err) {
    toast.error(handleApiError(err));
  }
};
```

---

## 8. Performance Optimization

### 8.1 Code Splitting Strategy
```typescript
// Route-based lazy loading
const LoginPage = lazy(() => import('./pages/LoginPage'));
const RegisterPage = lazy(() => import('./pages/RegisterPage'));
const DashboardPage = lazy(() => import('./pages/DashboardPage'));

// Component-based lazy loading
const TwoFactorSetupWizard = lazy(() => 
  import('./features/auth/components/TwoFactorSetupWizard')
);

// Suspense wrapper
<Suspense fallback={<LoadingSpinner />}>
  <Routes>
    <Route path="/login" element={<LoginPage />} />
    <Route path="/register" element={<RegisterPage />} />
  </Routes>
</Suspense>
```

### 8.2 Caching Strategy
- **RTK Query Cache**: 60s default, 5min for user profile
- **Component Memoization**: React.memo for expensive renders
- **Selector Memoization**: Reselect for derived state
- **Session Storage**: User preferences, UI state
- **Service Worker**: Static assets caching (future)

### 8.3 Performance Targets
- **Initial Load**: < 2s (TTI)
- **Route Transition**: < 100ms
- **Form Submission**: < 200ms (excluding API)
- **API Response Handling**: < 50ms
- **Bundle Size**: < 200KB (gzipped, initial)

### 8.4 Optimization Techniques
```typescript
// Debounced email availability check
const checkEmailAvailability = useCallback(
  debounce(async (email: string) => {
    const available = await api.checkEmail(email);
    setEmailAvailable(available);
  }, 500),
  []
);

// Memoized password strength calculation
const passwordStrength = useMemo(
  () => calculateStrength(password),
  [password]
);

// Virtualized list for security events
import { FixedSizeList } from 'react-window';

<FixedSizeList
  height={400}
  itemCount={securityEvents.length}
  itemSize={80}
>
  {({ index, style }) => (
    <SecurityEventCard event={securityEvents[index]} style={style} />
  )}
</FixedSizeList>
```

---

## 9. Testing Strategy

### 9.1 Testing Pyramid
- **Unit Tests**: 70% coverage - Components, hooks, utils
- **Integration Tests**: 20% coverage - Feature flows
- **E2E Tests**: 10% coverage - Critical user journeys

### 9.2 Unit Test Examples
```typescript
// Component Test
describe('LoginForm', () => {
  it('should validate email format', async () => {
    render(<LoginForm />);
    
    const emailInput = screen.getByLabelText(/email/i);
    await userEvent.type(emailInput, 'invalid-email');
    
    const submitButton = screen.getByRole('button', { name: /sign in/i });
    await userEvent.click(submitButton);
    
    expect(await screen.findByText(/invalid email/i)).toBeInTheDocument();
  });
  
  it('should call onSuccess when login succeeds', async () => {
    const onSuccess = vi.fn();
    const { container } = render(<LoginForm onSuccess={onSuccess} />);
    
    await userEvent.type(screen.getByLabelText(/email/i), 'test@example.com');
    await userEvent.type(screen.getByLabelText(/password/i), 'ValidPass123!');
    await userEvent.click(screen.getByRole('button', { name: /sign in/i }));
    
    await waitFor(() => expect(onSuccess).toHaveBeenCalled());
  });
});

// Hook Test
describe('useAuth', () => {
  it('should return authenticated user', () => {
    const mockUser = { id: '1', email: 'test@example.com' };
    const { result } = renderHook(() => useAuth(), {
      wrapper: ({ children }) => (
        <Provider store={mockStore({ auth: { user: mockUser } })}>
          {children}
        </Provider>
      )
    });
    
    expect(result.current.user).toEqual(mockUser);
    expect(result.current.isAuthenticated).toBe(true);
  });
});
```

### 9.3 Integration Test Example
```typescript
// Registration Flow Test
describe('User Registration Flow', () => {
  it('should complete full registration', async () => {
    render(<App />, { wrapper: TestProviders });
    
    // Navigate to registration
    await userEvent.click(screen.getByText(/sign up/i));
    
    // Fill form
    await userEvent.type(screen.getByLabelText(/email/i), 'new@example.com');
    await userEvent.type(screen.getByLabelText(/first name/i), 'John');
    await userEvent.type(screen.getByLabelText(/last name/i), 'Doe');
    await userEvent.type(screen.getByLabelText(/^password$/i), 'StrongPass123!');
    await userEvent.type(screen.getByLabelText(/confirm password/i), 'StrongPass123!');
    await userEvent.click(screen.getByLabelText(/gdpr consent/i));
    await userEvent.click(screen.getByLabelText(/terms/i));
    
    // Submit
    await userEvent.click(screen.getByRole('button', { name: /create account/i }));
    
    // Verify success
    await waitFor(() => {
      expect(screen.getByText(/verification email sent/i)).toBeInTheDocument();
    });
  });
});
```

### 9.4 E2E Test Example (Playwright)
```typescript
test('User can login with valid credentials', async ({ page }) => {
  await page.goto('/login');
  
  await page.fill('[name="email"]', 'test@example.com');
  await page.fill('[name="password"]', 'ValidPass123!');
  await page.click('button:has-text("Sign In")');
  
  await expect(page).toHaveURL('/dashboard');
  await expect(page.locator('text=Welcome')).toBeVisible();
});

test('User is locked out after 5 failed attempts', async ({ page }) => {
  await page.goto('/login');
  
  for (let i = 0; i < 5; i++) {
    await page.fill('[name="email"]', 'test@example.com');
    await page.fill('[name="password"]', 'WrongPassword');
    await page.click('button:has-text("Sign In")');
    await page.waitForSelector('text=/invalid credentials/i');
  }
  
  await expect(page.locator('text=/account locked/i')).toBeVisible();
});
```

---

## 10. Accessibility (WCAG 2.1 AA)

### 10.1 Keyboard Navigation
- **Tab Order**: Logical focus order through forms
- **Focus Indicators**: Visible 2px outline on focus
- **Keyboard Shortcuts**: Escape to close modals, Enter to submit
- **Skip Links**: "Skip to main content" link
- **Focus Trap**: Modal dialogs trap focus within

### 10.2 Screen Reader Support
```typescript
// Form Labels
<label htmlFor="email">
  Email Address
  <span className="sr-only">(required)</span>
</label>
<input
  id="email"
  type="email"
  aria-required="true"
  aria-invalid={errors.email ? 'true' : 'false'}
  aria-describedby={errors.email ? 'email-error' : undefined}
/>
{errors.email && (
  <span id="email-error" role="alert" className="error">
    {errors.email.message}
  </span>
)}

// Live Regions
<div role="status" aria-live="polite" aria-atomic="true">
  {isLoading ? 'Signing in...' : ''}
</div>

// Password Strength
<div
  role="progressbar"
  aria-valuemin={0}
  aria-valuemax={100}
  aria-valuenow={passwordStrength}
  aria-label="Password strength"
>
  <div style={{ width: `${passwordStrength}%` }} />
</div>
```

### 10.3 Color Contrast
- **Text**: 4.5:1 contrast ratio (normal text)
- **Large Text**: 3:1 contrast ratio (18pt+)
- **Interactive Elements**: 3:1 contrast ratio
- **Error Messages**: Not reliant on color alone

### 10.4 ARIA Patterns
- **Form Validation**: aria-invalid, aria-describedby
- **Required Fields**: aria-required="true"
- **Loading States**: aria-busy="true"
- **Error Announcements**: role="alert"
- **Modal Dialogs**: role="dialog", aria-modal="true"

---

## 11. Internationalization (i18n)

### 11.1 i18n Library Setup
```typescript
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';

i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources: {
      en: { translation: enTranslations },
      pt: { translation: ptTranslations },
      es: { translation: esTranslations }
    },
    fallbackLng: 'en',
    interpolation: {
      escapeValue: false
    }
  });
```

### 11.2 Translation Keys Structure
```json
{
  "auth": {
    "login": {
      "title": "Sign In",
      "emailLabel": "Email Address",
      "passwordLabel": "Password",
      "rememberMe": "Remember me",
      "forgotPassword": "Forgot password?",
      "submit": "Sign In",
      "noAccount": "Don't have an account?",
      "signUp": "Sign up"
    },
    "errors": {
      "invalidCredentials": "Invalid email or password",
      "accountLocked": "Account locked due to too many failed attempts",
      "emailNotVerified": "Please verify your email before signing in"
    }
  }
}
```

### 11.3 Usage in Components
```typescript
import { useTranslation } from 'react-i18next';

const LoginForm = () => {
  const { t } = useTranslation();
  
  return (
    <form>
      <h1>{t('auth.login.title')}</h1>
      <label>{t('auth.login.emailLabel')}</label>
      <input type="email" placeholder={t('auth.login.emailPlaceholder')} />
      <button>{t('auth.login.submit')}</button>
    </form>
  );
};
```

---

## 12. Error Handling & User Feedback

### 12.1 Error Boundary
```typescript
class AuthErrorBoundary extends React.Component<Props, State> {
  state = { hasError: false, error: null };
  
  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }
  
  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    logger.error('Auth component error', { error, errorInfo });
    
    // Send to error tracking service
    Sentry.captureException(error, { contexts: { react: errorInfo } });
  }
  
  render() {
    if (this.state.hasError) {
      return (
        <ErrorFallback
          error={this.state.error}
          resetError={() => this.setState({ hasError: false })}
        />
      );
    }
    
    return this.props.children;
  }
}
```

### 12.2 Toast Notifications
```typescript
import { toast } from 'react-hot-toast';

// Success
toast.success('Account created successfully!', {
  duration: 4000,
  position: 'top-right',
  icon: '✅'
});

// Error
toast.error('Failed to send verification email', {
  duration: 6000,
  position: 'top-right',
  icon: '❌'
});

// Custom
toast.custom((t) => (
  <SecurityAlert
    visible={t.visible}
    message="New device detected"
    onDismiss={() => toast.dismiss(t.id)}
  />
));
```

### 12.3 Form Error Display
```typescript
// Field-level errors
{errors.email && (
  <span className="error-message" role="alert">
    <Icon name="alert" />
    {errors.email.message}
  </span>
)}

// Form-level errors
{submitError && (
  <div className="form-error" role="alert">
    <Icon name="error" />
    <div>
      <strong>Unable to sign in</strong>
      <p>{submitError}</p>
    </div>
  </div>
)}
```

### 12.4 Loading States
```typescript
// Button loading state
<button type="submit" disabled={isLoading}>
  {isLoading ? (
    <>
      <LoadingSpinner size="sm" />
      <span>Signing in...</span>
    </>
  ) : (
    'Sign In'
  )}
</button>

// Skeleton loading
{isLoading ? (
  <Skeleton count={3} height={60} />
) : (
  <SessionList sessions={sessions} />
)}
```

---

## 13. Mobile Responsiveness

### 13.1 Breakpoints
```css
/* Mobile First Approach */
:root {
  --breakpoint-sm: 640px;
  --breakpoint-md: 768px;
  --breakpoint-lg: 1024px;
  --breakpoint-xl: 1280px;
}

/* Base styles (mobile) */
.login-form {
  padding: 1rem;
}

/* Tablet */
@media (min-width: 768px) {
  .login-form {
    padding: 2rem;
    max-width: 400px;
    margin: 0 auto;
  }
}

/* Desktop */
@media (min-width: 1024px) {
  .login-form {
    padding: 3rem;
    max-width: 500px;
  }
}
```

### 13.2 Touch Targets
- **Minimum Size**: 44x44px (iOS), 48x48px (Android)
- **Spacing**: 8px minimum between interactive elements
- **Gestures**: Swipe to dismiss modals, pull to refresh

### 13.3 Mobile-Specific Features
```typescript
// Biometric authentication detection
const isBiometricAvailable = async () => {
  if ('PublicKeyCredential' in window) {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  }
  return false;
};

// iOS/Android specific behavior
const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);

if (isMobile) {
  // Show biometric login option
  // Adjust keyboard behavior
  // Enable touch gestures
}
```

### 13.4 PWA Considerations
```json
// manifest.json
{
  "name": "SUMA Finance",
  "short_name": "SUMA",
  "start_url": "/",
  "display": "standalone",
  "theme_color": "#1a73e8",
  "background_color": "#ffffff",
  "icons": [
    {
      "src": "/icons/icon-192.png",
      "sizes": "192x192",
      "type": "image/png"
    },
    {
      "src": "/icons/icon-512.png",
      "sizes": "512x512",
      "type": "image/png"
    }
  ]
}
```

---

## 14. Monitoring & Analytics

### 14.1 Error Tracking
```typescript
// Sentry Integration
import * as Sentry from '@sentry/react';

Sentry.init({
  dsn: process.env.VITE_SENTRY_DSN,
  environment: process.env.VITE_ENVIRONMENT,
  integrations: [
    new Sentry.BrowserTracing(),
    new Sentry.Replay()
  ],
  tracesSampleRate: 0.1,
  replaysSessionSampleRate: 0.1,
  replaysOnErrorSampleRate: 1.0,
  beforeSend(event, hint) {
    // Filter out sensitive data
    if (event.request) {
      delete event.request.cookies;
      delete event.request.headers?.Authorization;
    }
    return event;
  }
});

// Custom error logging
const logAuthError = (error: Error, context: Record<string, any>) => {
  Sentry.captureException(error, {
    tags: { feature: 'authentication' },
    contexts: { auth: context }
  });
};
```

### 14.2 Performance Monitoring
```typescript
// Web Vitals
import { getCLS, getFID, getFCP, getLCP, getTTFB } from 'web-vitals';

getCLS(console.log);
getFID(console.log);
getFCP(console.log);
getLCP(console.log);
getTTFB(console.log);

// Custom performance marks
performance.mark('login-start');
// ... login logic
performance.mark('login-end');
performance.measure('login-duration', 'login-start', 'login-end');
```

### 14.3 Analytics Events
```typescript
// Analytics wrapper
const analytics = {
  track: (event: string, properties?: Record<string, any>) => {
    // Send to analytics service (e.g., Mixpanel, Amplitude)
    window.analytics?.track(event, properties);
  }
};

// Authentication events
analytics.track('User Registered', {
  method: 'email',
  hasMarketingConsent: formData.marketingConsent
});

analytics.track('User Logged In', {
  method: 'email',
  twoFactorEnabled: user.twoFactorEnabled
});

analytics.track('Password Reset Requested', {
  email: formData.email
});
```

---

## 15. Build & Deployment

### 15.1 Vite Configuration
```typescript
// vite.config.ts
import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import { splitVendorChunkPlugin } from 'vite';

export default defineConfig({
  plugins: [react(), splitVendorChunkPlugin()],
  build: {
    target: 'es2015',
    outDir: 'dist',
    sourcemap: true,
    rollupOptions: {
      output: {
        manualChunks: {
          'react-vendor': ['react', 'react-dom', 'react-router-dom'],
          'redux-vendor': ['@reduxjs/toolkit', 'react-redux'],
          'form-vendor': ['react-hook-form', 'zod']
        }
      }
    },
    chunkSizeWarningLimit: 500
  },
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true
      }
    }
  }
});
```

### 15.2 Environment Variables
```bash
# .env.development
VITE_API_URL=http://localhost:8080/api/v1
VITE_ENVIRONMENT=development
VITE_SENTRY_DSN=
VITE_ENABLE_ANALYTICS=false

# .env.production
VITE_API_URL=https://api.suma.finance/v1
VITE_ENVIRONMENT=production
VITE_SENTRY_DSN=https://xxx@sentry.io/xxx
VITE_ENABLE_ANALYTICS=true
```

### 15.3 CI/CD Pipeline (GitHub Actions)
```yaml
name: Frontend CI/CD

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
      
      - run: npm ci
      - run: npm run lint
      - run: npm run type-check
      - run: npm run test:coverage
      
      - name: Upload coverage
        uses: codecov/codecov-action@v3
  
  build:
    runs-on: ubuntu-latest
    needs: test
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - run: npm ci
      - run: npm run build
      
      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: dist
          path: dist/
  
  deploy:
    runs-on: ubuntu-latest
    needs: build
    if: github.ref == 'refs/heads/main'
    steps:
      - uses: actions/download-artifact@v3
        with:
          name: dist
      
      - name: Deploy to S3
        run: |
          aws s3 sync dist/ s3://suma-finance-frontend/ --delete
          aws cloudfront create-invalidation --distribution-id XXX --paths "/*"
```

---

## 16. Future Enhancements

### 16.1 Planned Features
1. **Passkey/WebAuthn Support** (Q2 2026)
   - Passwordless authentication
   - Device-based authentication
   - Biometric integration

2. **Social Login Expansion** (Q3 2026)
   - Facebook Login
   - Microsoft Account
   - GitHub OAuth

3. **Advanced Security** (Q4 2026)
   - Risk-based authentication
   - Behavioral biometrics
   - Fraud detection

4. **Offline Support** (Q1 2027)
   - Service worker implementation
   - Offline session management
   - Sync on reconnection

### 16.2 Technical Debt
- Migrate to React 19 when stable
- Implement Suspense for data fetching
- Refactor Redux to use RTK Query exclusively
- Add Storybook for component documentation

---

## 17. Documentation & Resources

### 17.1 Internal Documentation
- **Component Library**: Storybook (http://localhost:6006)
- **API Documentation**: Swagger UI (http://localhost:8080/docs)
- **Architecture Diagrams**: Mermaid diagrams in /docs
- **Runbooks**: /docs/runbooks/

### 17.2 External Resources
- React Documentation: https://react.dev
- Redux Toolkit: https://redux-toolkit.js.org
- React Hook Form: https://react-hook-form.com
- OWASP Top 10: https://owasp.org/www-project-top-ten/
- WCAG 2.1: https://www.w3.org/WAI/WCAG21/quickref/

### 17.3 Team Contacts
- **Frontend Lead**: [Name] ([email])
- **Security Team**: security@suma.finance
- **DevOps**: devops@suma.finance

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Next Review**: 2026-01-29
