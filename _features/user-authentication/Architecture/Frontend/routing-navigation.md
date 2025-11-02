```markdown
# arch-routing-navigation-generator

**Project**: SUMA Finance
**Feature**: User Registration & Authentication
**Domain**: Authentication & Authorization
**Generated**: 2025-10-29T00:00:00Z

---

## 1. Routing Architecture Overview

### 1.1 Route Categorization

**Public Routes** (No Authentication Required)
- `/auth/register` - User registration endpoint
- `/auth/login` - User login endpoint
- `/auth/verify-email` - Email verification callback
- `/auth/resend-verification` - Resend verification email
- `/auth/forgot-password` - Initiate password reset
- `/auth/reset-password` - Complete password reset
- `/auth/refresh-token` - Refresh access token (requires valid refresh token)

**Protected Routes** (Requires Authentication)
- `/auth/logout` - Terminate user session
- `/auth/change-password` - Change password for authenticated user
- `/auth/enable-2fa` - Enable two-factor authentication
- `/auth/verify-2fa` - Verify 2FA setup
- `/auth/disable-2fa` - Disable two-factor authentication
- `/auth/backup-codes` - Generate/retrieve 2FA backup codes
- `/auth/sessions` - List active sessions
- `/auth/sessions/:id` - Revoke specific session
- `/auth/devices` - List trusted devices
- `/auth/devices/:id` - Remove trusted device
- `/auth/consent` - View/manage GDPR consents
- `/auth/consent/withdraw` - Withdraw specific consent

**Admin Routes** (Requires Admin Role)
- `/admin/auth/users/:id/unlock` - Unlock locked account
- `/admin/auth/users/:id/force-logout` - Force logout user
- `/admin/auth/audit-logs` - View security audit logs
- `/admin/auth/sessions` - View all active sessions

### 1.2 HTTP Methods Mapping

| Endpoint | Methods | Purpose |
|----------|---------|---------|
| `/auth/register` | POST | Create new user account |
| `/auth/login` | POST | Authenticate user, issue JWT |
| `/auth/logout` | POST | Terminate session, blacklist refresh token |
| `/auth/verify-email` | GET, POST | Verify email with token |
| `/auth/resend-verification` | POST | Resend verification email |
| `/auth/forgot-password` | POST | Request password reset email |
| `/auth/reset-password` | POST | Reset password with token |
| `/auth/change-password` | PUT | Change password for authenticated user |
| `/auth/refresh-token` | POST | Issue new access token |
| `/auth/enable-2fa` | POST | Enable 2FA, send OTP |
| `/auth/verify-2fa` | POST | Verify OTP, complete 2FA setup |
| `/auth/disable-2fa` | DELETE | Disable 2FA with password confirmation |
| `/auth/backup-codes` | GET, POST | Retrieve or regenerate backup codes |
| `/auth/sessions` | GET, DELETE | List sessions, revoke all sessions |
| `/auth/sessions/:id` | DELETE | Revoke specific session |
| `/auth/devices` | GET | List trusted devices |
| `/auth/devices/:id` | DELETE | Remove trusted device |
| `/auth/consent` | GET, PUT | View or update consents |
| `/auth/consent/withdraw` | POST | Withdraw specific consent |

---

## 2. Navigation Flow Architecture

### 2.1 User Registration Flow

```
START
  ↓
[Registration Form]
  ↓ (POST /auth/register)
[Backend: Validate Input]
  ↓
[Backend: Check Email Uniqueness]
  ↓
[Backend: Hash Password (Argon2id)]
  ↓
[Backend: Store User (pending verification)]
  ↓
[Backend: Generate Verification Token (HMAC-SHA256)]
  ↓
[Backend: Send Verification Email (SendGrid)]
  ↓
[Response: 201 Created]
  ↓
[Frontend: Show "Check Email" Screen]
  ↓
[User: Click Email Link]
  ↓ (GET /auth/verify-email?token=xxx)
[Backend: Verify Token Signature]
  ↓
[Backend: Check Token Expiry (24h)]
  ↓
[Backend: Activate User Account]
  ↓
[Backend: Log Security Event]
  ↓
[Redirect: /login with success message]
END
```

**Alternate Paths:**
- Email already exists → Return 409 Conflict
- Invalid token → Return 400 Bad Request, show resend option
- Expired token → Return 410 Gone, auto-resend new token
- Resend request → Rate limit: 1 per 2 minutes per email

### 2.2 Login Flow (Without 2FA)

```
START
  ↓
[Login Form]
  ↓ (POST /auth/login)
[Backend: Rate Limit Check (5/min per IP)]
  ↓
[Backend: Fetch User by Email]
  ↓
[Backend: Verify Password (Argon2id)]
  ↓
[Backend: Check Account Status (active, locked, pending)]
  ↓
[Backend: Check Failed Attempt Count]
  ↓
[Backend: Generate Access Token (15 min, JWT)]
  ↓
[Backend: Generate Refresh Token (7 days, opaque)]
  ↓
[Backend: Store Session in Redis]
  ↓
[Backend: Device Fingerprinting]
  ↓
[Backend: Log Security Event (IP, timestamp, device)]
  ↓
[Response: 200 OK with tokens + user object]
  ↓
[Frontend: Store Access Token (memory)]
  ↓
[Frontend: Store Refresh Token (HttpOnly cookie)]
  ↓
[Redirect: /dashboard]
END
```

**Error Paths:**
- Invalid credentials → Increment failed attempts, return generic error (prevent email enumeration)
- Account locked → Return 423 Locked with unlock time
- Failed attempt threshold (5) → Lock account for 15 minutes
- Email not verified → Return 403 Forbidden with resend option

### 2.3 Login Flow (With 2FA Enabled)

```
START
  ↓
[Login Form]
  ↓ (POST /auth/login)
[Backend: Verify Password (as above)]
  ↓
[Backend: Detect 2FA Enabled]
  ↓
[Backend: Generate 6-digit OTP]
  ↓
[Backend: Store OTP in Redis (5 min TTL)]
  ↓
[Backend: Send OTP via Email (SendGrid)]
  ↓
[Backend: Issue Temporary Token (5 min, limited scope)]
  ↓
[Response: 200 OK with requires_2fa: true]
  ↓
[Frontend: Redirect to 2FA Input Screen]
  ↓
[User: Enter OTP]
  ↓ (POST /auth/verify-2fa with temp token)
[Backend: Rate Limit (3 attempts per 5 min)]
  ↓
[Backend: Verify OTP from Redis]
  ↓
[Backend: Issue Full Access Token]
  ↓
[Backend: Issue Refresh Token]
  ↓
[Backend: Invalidate OTP]
  ↓
[Backend: Log Security Event]
  ↓
[Response: 200 OK with tokens]
  ↓
[Redirect: /dashboard]
END
```

**Error Paths:**
- Invalid OTP → Increment attempt count, return 401
- OTP expired → Return 410 Gone, offer resend
- Too many attempts (3) → Invalidate temp token, restart login
- Backup code path → Alternative verification method

### 2.4 Password Reset Flow

```
START
  ↓
[Forgot Password Form]
  ↓ (POST /auth/forgot-password)
[Backend: Rate Limit (3 per hour per email)]
  ↓
[Backend: Fetch User by Email]
  ↓
[Backend: Generate Reset Token (HMAC-SHA256, 1h expiry)]
  ↓
[Backend: Store Token Hash in Database]
  ↓
[Backend: Send Reset Email (SendGrid)]
  ↓
[Backend: Log Security Event]
  ↓
[Response: 200 OK (generic, prevent enumeration)]
  ↓
[Frontend: Show "Check Email" Screen]
  ↓
[User: Click Reset Link]
  ↓ (GET /auth/reset-password?token=xxx)
[Frontend: Show Reset Password Form]
  ↓ (POST /auth/reset-password)
[Backend: Verify Token Signature]
  ↓
[Backend: Check Token Expiry (1h)]
  ↓
[Backend: Validate New Password Complexity]
  ↓
[Backend: Check Password History (last 5)]
  ↓
[Backend: Hash New Password (Argon2id)]
  ↓
[Backend: Update Password]
  ↓
[Backend: Invalidate All Sessions (force re-login)]
  ↓
[Backend: Blacklist All Refresh Tokens]
  ↓
[Backend: Send Confirmation Email]
  ↓
[Backend: Log Security Event]
  ↓
[Response: 200 OK]
  ↓
[Redirect: /login with success message]
END
```

**Error Paths:**
- Invalid token → Return 400 Bad Request
- Expired token → Return 410 Gone, offer new reset
- Password reused → Return 422, show history requirement

### 2.5 Session Refresh Flow

```
START
  ↓
[Access Token Expires (15 min)]
  ↓
[Frontend: Detect 401 on API Call]
  ↓
[Frontend: Automatic Refresh Attempt]
  ↓ (POST /auth/refresh-token with HttpOnly cookie)
[Backend: Extract Refresh Token from Cookie]
  ↓
[Backend: Verify Token Signature]
  ↓
[Backend: Check Token Not Blacklisted]
  ↓
[Backend: Fetch Session from Redis]
  ↓
[Backend: Check Session Validity]
  ↓
[Backend: Detect Reuse (already rotated)]
  ↓
[Backend: Issue New Access Token (15 min)]
  ↓
[Backend: Issue New Refresh Token (7 days)]
  ↓
[Backend: Blacklist Old Refresh Token]
  ↓
[Backend: Update Session in Redis]
  ↓
[Backend: Log Security Event]
  ↓
[Response: 200 OK with new tokens]
  ↓
[Frontend: Store New Access Token]
  ↓
[Frontend: Retry Original API Call]
END
```

**Error Paths:**
- Refresh token reuse detected → Blacklist entire token family, force logout all devices
- Refresh token expired → Return 401, redirect to login
- Session not found → Return 401, redirect to login

### 2.6 Logout Flow

```
START
  ↓
[User: Click Logout Button]
  ↓ (POST /auth/logout)
[Backend: Extract Refresh Token from Cookie]
  ↓
[Backend: Blacklist Refresh Token]
  ↓
[Backend: Delete Session from Redis]
  ↓
[Backend: Clear Refresh Token Cookie]
  ↓
[Backend: Log Security Event]
  ↓
[Response: 200 OK]
  ↓
[Frontend: Clear Access Token from Memory]
  ↓
[Frontend: Clear Application State]
  ↓
[Redirect: /login]
END
```

**Additional Actions:**
- Logout from all devices → Blacklist all user's refresh tokens
- Admin force logout → Same mechanism, triggered by admin

---

## 3. Frontend Routing Structure (React)

### 3.1 Route Configuration (React Router v6)

```typescript
// routes/authRoutes.tsx
import { RouteObject } from 'react-router-dom';
import { PublicRoute, ProtectedRoute } from '@/components/RouteGuards';

export const authRoutes: RouteObject[] = [
  // Public Routes
  {
    path: '/register',
    element: <PublicRoute><RegisterPage /></PublicRoute>,
  },
  {
    path: '/login',
    element: <PublicRoute><LoginPage /></PublicRoute>,
  },
  {
    path: '/verify-email',
    element: <PublicRoute><VerifyEmailPage /></PublicRoute>,
  },
  {
    path: '/forgot-password',
    element: <PublicRoute><ForgotPasswordPage /></PublicRoute>,
  },
  {
    path: '/reset-password',
    element: <PublicRoute><ResetPasswordPage /></PublicRoute>,
  },
  {
    path: '/2fa-verify',
    element: <PublicRoute><TwoFactorVerifyPage /></PublicRoute>,
  },
  
  // Protected Routes
  {
    path: '/account',
    element: <ProtectedRoute><AccountLayout /></ProtectedRoute>,
    children: [
      {
        path: 'security',
        element: <SecuritySettingsPage />,
      },
      {
        path: 'sessions',
        element: <SessionsPage />,
      },
      {
        path: 'devices',
        element: <DevicesPage />,
      },
      {
        path: 'consents',
        element: <ConsentsPage />,
      },
    ],
  },
];
```

### 3.2 Route Guards

```typescript
// components/RouteGuards.tsx
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';

export const PublicRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  
  if (isAuthenticated) {
    const from = location.state?.from?.pathname || '/dashboard';
    return <Navigate to={from} replace />;
  }
  
  return <>{children}</>;
};

export const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();
  const location = useLocation();
  
  if (isLoading) {
    return <LoadingSpinner />;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  
  return <>{children}</>;
};

export const AdminRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, user } = useAuth();
  const location = useLocation();
  
  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }
  
  if (!user?.roles.includes('admin')) {
    return <Navigate to="/403" replace />;
  }
  
  return <>{children}</>;
};
```

### 3.3 Navigation Components

**Main Navigation (Authenticated State)**
```typescript
// components/MainNav.tsx
const MainNav: React.FC = () => {
  const { user, logout } = useAuth();
  
  return (
    <nav>
      <NavLink to="/dashboard">Dashboard</NavLink>
      <NavLink to="/transactions">Transactions</NavLink>
      <NavLink to="/budget">Budget</NavLink>
      
      <UserMenu>
        <NavLink to="/account/security">Security Settings</NavLink>
        <NavLink to="/account/sessions">Active Sessions</NavLink>
        <NavLink to="/account/consents">Privacy & Consents</NavLink>
        <button onClick={logout}>Logout</button>
      </UserMenu>
    </nav>
  );
};
```

---

## 4. Backend Routing Structure (Go/Gin)

### 4.1 Router Configuration

```go
// internal/routes/auth_routes.go
package routes

import (
    "github.com/gin-gonic/gin"
    "suma-finance/internal/controllers"
    "suma-finance/internal/middleware"
)

func SetupAuthRoutes(router *gin.Engine, authController *controllers.AuthController) {
    authGroup := router.Group("/auth")
    {
        // Public routes
        authGroup.POST("/register", authController.Register)
        authGroup.POST("/login", middleware.RateLimit("5-M"), authController.Login)
        authGroup.GET("/verify-email", authController.VerifyEmail)
        authGroup.POST("/resend-verification", middleware.RateLimit("1-2M"), authController.ResendVerification)
        authGroup.POST("/forgot-password", middleware.RateLimit("3-H"), authController.ForgotPassword)
        authGroup.POST("/reset-password", authController.ResetPassword)
        authGroup.POST("/refresh-token", authController.RefreshToken)
        
        // Protected routes (require JWT)
        protected := authGroup.Group("")
        protected.Use(middleware.RequireAuth())
        {
            protected.POST("/logout", authController.Logout)
            protected.PUT("/change-password", authController.ChangePassword)
            protected.POST("/enable-2fa", authController.Enable2FA)
            protected.POST("/verify-2fa", authController.Verify2FA)
            protected.DELETE("/disable-2fa", authController.Disable2FA)
            protected.GET("/backup-codes", authController.GetBackupCodes)
            protected.POST("/backup-codes", authController.RegenerateBackupCodes)
            protected.GET("/sessions", authController.ListSessions)
            protected.DELETE("/sessions", authController.RevokeAllSessions)
            protected.DELETE("/sessions/:id", authController.RevokeSession)
            protected.GET("/devices", authController.ListDevices)
            protected.DELETE("/devices/:id", authController.RemoveDevice)
            protected.GET("/consent", authController.GetConsents)
            protected.PUT("/consent", authController.UpdateConsents)
            protected.POST("/consent/withdraw", authController.WithdrawConsent)
        }
    }
    
    // Admin routes
    adminGroup := router.Group("/admin/auth")
    adminGroup.Use(middleware.RequireAuth(), middleware.RequireRole("admin"))
    {
        adminGroup.POST("/users/:id/unlock", authController.UnlockAccount)
        adminGroup.POST("/users/:id/force-logout", authController.ForceLogout)
        adminGroup.GET("/audit-logs", authController.GetAuditLogs)
        adminGroup.GET("/sessions", authController.GetAllSessions)
    }
}
```

### 4.2 Middleware Chain

```go
// internal/middleware/auth.go
package middleware

func RequireAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Extract JWT from Authorization header
        token := extractToken(c)
        if token == "" {
            c.JSON(401, gin.H{"error": "unauthorized"})
            c.Abort()
            return
        }
        
        // Verify JWT signature and expiration
        claims, err := verifyToken(token)
        if err != nil {
            c.JSON(401, gin.H{"error": "invalid_token"})
            c.Abort()
            return
        }
        
        // Check if session exists in Redis
        sessionExists, err := checkSession(c, claims.UserID, claims.SessionID)
        if err != nil || !sessionExists {
            c.JSON(401, gin.H{"error": "session_expired"})
            c.Abort()
            return
        }
        
        // Inject user context
        c.Set("user_id", claims.UserID)
        c.Set("session_id", claims.SessionID)
        c.Set("roles", claims.Roles)
        
        c.Next()
    }
}

func RequireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        roles, exists := c.Get("roles")
        if !exists {
            c.JSON(403, gin.H{"error": "forbidden"})
            c.Abort()
            return
        }
        
        userRoles := roles.([]string)
        if !contains(userRoles, role) {
            c.JSON(403, gin.H{"error": "insufficient_permissions"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}

func RateLimit(rule string) gin.HandlerFunc {
    // Implement Redis-backed rate limiting
    // Format: "{count}-{period}" e.g., "5-M" = 5 per minute
    return func(c *gin.Context) {
        key := buildRateLimitKey(c, rule)
        allowed, err := checkRateLimit(key, rule)
        
        if err != nil || !allowed {
            c.JSON(429, gin.H{"error": "rate_limit_exceeded"})
            c.Abort()
            return
        }
        
        c.Next()
    }
}
```

---

## 5. Mobile Navigation (React Native)

### 5.1 Stack Navigation

```typescript
// navigation/AuthStack.tsx
import { createStackNavigator } from '@react-navigation/stack';

const AuthStack = createStackNavigator();

export const AuthNavigator = () => {
  return (
    <AuthStack.Navigator
      screenOptions={{
        headerShown: false,
        cardStyleInterpolator: CardStyleInterpolators.forHorizontalIOS,
      }}
    >
      <AuthStack.Screen name="Welcome" component={WelcomeScreen} />
      <AuthStack.Screen name="Login" component={LoginScreen} />
      <AuthStack.Screen name="Register" component={RegisterScreen} />
      <AuthStack.Screen name="VerifyEmail" component={VerifyEmailScreen} />
      <AuthStack.Screen name="ForgotPassword" component={ForgotPasswordScreen} />
      <AuthStack.Screen name="ResetPassword" component={ResetPasswordScreen} />
      <AuthStack.Screen name="TwoFactorVerify" component={TwoFactorVerifyScreen} />
    </AuthStack.Navigator>
  );
};

// navigation/AppStack.tsx
const AppStack = createStackNavigator();

export const AppNavigator = () => {
  return (
    <AppStack.Navigator>
      <AppStack.Screen name="MainTabs" component={MainTabNavigator} />
      <AppStack.Screen name="SecuritySettings" component={SecuritySettingsScreen} />
      <AppStack.Screen name="SessionsManagement" component={SessionsScreen} />
      <AppStack.Screen name="DevicesManagement" component={DevicesScreen} />
      <AppStack.Screen name="ConsentsManagement" component={ConsentsScreen} />
    </AppStack.Navigator>
  );
};
```

### 5.2 Deep Linking Configuration

```typescript
// navigation/linking.ts
export const linkingConfiguration = {
  prefixes: ['sumafinance://', 'https://app.sumafinance.com'],
  config: {
    screens: {
      Auth: {
        screens: {
          VerifyEmail: {
            path: 'verify-email',
            parse: {
              token: (token: string) => token,
            },
          },
          ResetPassword: {
            path: 'reset-password',
            parse: {
              token: (token: string) => token,
            },
          },
        },
      },
      App: {
        screens: {
          MainTabs: {
            screens: {
              Dashboard: 'dashboard',
              Transactions: 'transactions',
            },
          },
        },
      },
    },
  },
};
```

---

## 6. URL Structure & Deep Linking

### 6.1 Frontend URLs

**Web Application**
```
https://app.sumafinance.com/register
https://app.sumafinance.com/login
https://app.sumafinance.com/verify-email?token={token}
https://app.sumafinance.com/reset-password?token={token}
https://app.sumafinance.com/2fa-verify
https://app.sumafinance.com/account/security
https://app.sumafinance.com/account/sessions
https://app.sumafinance.com/account/devices
https://app.sumafinance.com/account/consents
```

**Mobile Deep Links**
```
sumafinance://verify-email?token={token}
sumafinance://reset-password?token={token}
sumafinance://dashboard
```

### 6.2 API Endpoints

**Base URL**: `https://api.sumafinance.com/v1`

```
POST   /auth/register
POST   /auth/login
POST   /auth/logout
GET    /auth/verify-email?token={token}
POST   /auth/resend-verification
POST   /auth/forgot-password
POST   /auth/reset-password
PUT    /auth/change-password
POST   /auth/refresh-token
POST   /auth/enable-2fa
POST   /auth/verify-2fa
DELETE /auth/disable-2fa
GET    /auth/backup-codes
POST   /auth/backup-codes
GET    /auth/sessions
DELETE /auth/sessions
DELETE /auth/sessions/{id}
GET    /auth/devices
DELETE /auth/devices/{id}
GET    /auth/consent
PUT    /auth/consent
POST   /auth/consent/withdraw
POST   /admin/auth/users/{id}/unlock
POST   /admin/auth/users/{id}/force-logout
GET    /admin/auth/audit-logs
GET    /admin/auth/sessions
```

---

## 7. Navigation State Management

### 7.1 Authentication Context

```typescript
// contexts/AuthContext.tsx
import { createContext, useContext, useState, useEffect } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

interface AuthContextType {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshToken: () => Promise<void>;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const navigate = useNavigate();
  const location = useLocation();
  
  // Check for existing session on mount
  useEffect(() => {
    checkAuthStatus();
  }, []);
  
  // Setup axios interceptor for automatic token refresh
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401 && !error.config._retry) {
          error.config._retry = true;
          try {
            await refreshToken();
            return axios(error.config);
          } catch (refreshError) {
            await logout();
            return Promise.reject(refreshError);
          }
        }
        return Promise.reject(error);
      }
    );
    
    return () => axios.interceptors.response.eject(interceptor);
  }, []);
  
  const checkAuthStatus = async () => {
    try {
      // Try to use existing access token or refresh
      const token = getAccessToken();
      if (token) {
        const userData = await api.getCurrentUser();
        setUser(userData);
      }
    } catch (error) {
      // Token invalid or expired, try refresh
      try {
        await refreshToken();
      } catch (refreshError) {
        // Refresh failed, user is not authenticated
      }
    } finally {
      setIsLoading(false);
    }
  };
  
  const login = async (email: string, password: string) => {
    const response = await api.login({ email, password });
    
    if (response.requires_2fa) {
      // Store temporary token and navigate to 2FA
      setTempToken(response.temp_token);
      navigate('/2fa-verify');
      return;
    }
    
    // Store tokens and user data
    setAccessToken(response.access_token);
    setUser(response.user);
    
    // Navigate to intended destination or dashboard
    const from = location.state?.from?.pathname || '/dashboard';
    navigate(from, { replace: true });
  };
  
  const logout = async () => {
    try {
      await api.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      clearAccessToken();
      setUser(null);
      navigate('/login', { replace: true });
    }
  };
  
  const refreshToken = async () => {
    const response = await api.refreshToken();
    setAccessToken(response.access_token);
    
    if (!user) {
      const userData = await api.getCurrentUser();
      setUser(userData);
    }
  };
  
  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        logout,
        refreshToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within AuthProvider');
  }
  return context;
};
```

### 7.2 Token Storage Strategy

**Web (React)**
- Access Token: In-memory (React state/context)
- Refresh Token: HttpOnly, Secure, SameSite=Strict cookie

**Mobile (React Native)**
- Access Token: In-memory (React state/context)
- Refresh Token: Secure storage (iOS Keychain, Android KeyStore)

```typescript
// utils/tokenStorage.ts (Mobile)
import * as SecureStore from 'expo-secure-store';

export const setRefreshToken = async (token: string) => {
  await SecureStore.setItemAsync('refresh_token', token, {
    keychainAccessible: SecureStore.WHEN_UNLOCKED,
  });
};

export const getRefreshToken = async (): Promise<string | null> => {
  return await SecureStore.getItemAsync('refresh_token');
};

export const clearRefreshToken = async () => {
  await SecureStore.deleteItemAsync('refresh_token');
};
```

---

## 8. Navigation Security Considerations

### 8.1 CSRF Protection

- All state-changing requests (POST, PUT, DELETE) require CSRF token
- CSRF token included in hidden form field or custom header
- Validated on backend against session

```typescript
// hooks/useCsrfToken.ts
export const useCsrfToken = () => {
  const [csrfToken, setCsrfToken] = useState('');
  
  useEffect(() => {
    // Fetch CSRF token on component mount
    api.getCsrfToken().then(setCsrfToken);
  }, []);
  
  return csrfToken;
};

// Axios interceptor
axios.interceptors.request.use((config) => {
  const csrfToken = getCsrfToken();
  if (csrfToken && ['post', 'put', 'delete'].includes(config.method)) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  return config;
});
```

### 8.2 Redirect Validation

- Validate all redirects against allowlist
- Prevent open redirect vulnerabilities
- Sanitize `returnUrl` parameters

```go
// internal/utils/redirect.go
func ValidateRedirect(url string) bool {
    allowedDomains := []string{
        "app.sumafinance.com",
        "sumafinance.com",
    }
    
    parsedURL, err := url.Parse(url)
    if err != nil {
        return false
    }
    
    // Only allow relative URLs or URLs from allowed domains
    if parsedURL.Host == "" {
        return true // Relative URL
    }
    
    for _, domain := range allowedDomains {
        if strings.HasSuffix(parsedURL.Host, domain) {
            return true
        }
    }
    
    return false
}
```

### 8.3 Session Timeout Handling

- Idle timeout: 15 minutes
- Absolute timeout: 8 hours
- Warning dialog at 1 minute before timeout
- Grace period for user action

```typescript
// hooks/useSessionTimeout.ts
export const useSessionTimeout = () => {
  const { logout } = useAuth();
  const [showWarning, setShowWarning] = useState(false);
  
  const IDLE_TIMEOUT = 15 * 60 * 1000; // 15 minutes
  const WARNING_BEFORE = 60 * 1000; // 1 minute
  
  let timeoutId: NodeJS.Timeout;
  let warningId: NodeJS.Timeout;
  
  const resetTimeout = () => {
    clearTimeout(timeoutId);
    clearTimeout(warningId);
    
    warningId = setTimeout(() => {
      setShowWarning(true);
    }, IDLE_TIMEOUT - WARNING_BEFORE);
    
    timeoutId = setTimeout(() => {
      logout();
    }, IDLE_TIMEOUT);
  };
  
  useEffect(() => {
    const events = ['mousedown', 'keydown', 'scroll', 'touchstart'];
    
    events.forEach(event => {
      document.addEventListener(event, resetTimeout);
    });
    
    resetTimeout();
    
    return () => {
      events.forEach(event => {
        document.removeEventListener(event, resetTimeout);
      });
      clearTimeout(timeoutId);
      clearTimeout(warningId);
    };
  }, []);
  
  return { showWarning, extendSession: resetTimeout };
};
```

---

## 9. Error Handling & User Feedback

### 9.1 Navigation Error States

| Error Code | Scenario | User Action | Navigation |
|------------|----------|-------------|------------|
| 401 | Unauthorized | Show login prompt | Redirect to /login |
| 403 | Forbidden | Show access denied | Stay on current page |
| 404 | Not found | Show 404 page | /404 |
| 410 | Token expired | Show resend option | Stay on verification page |
| 423 | Account locked | Show unlock timer | Stay on login page |
| 429 | Rate limited | Show retry timer | Stay on current page |
| 500 | Server error | Show error page | /error |

### 9.2 Loading States

```typescript
// components/LoadingBoundary.tsx
export const LoadingBoundary: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isLoading } = useAuth();
  
  if (isLoading) {
    return (
      <div className="loading-screen">
        <Spinner />
        <p>Loading your account...</p>
      </div>
    );
  }
  
  return <>{children}</>;
};
```

### 9.3 Success Feedback

- Toast notifications for actions (logout, password changed)
- Confirmation pages for critical actions (email verified, 2FA enabled)
- Progress indicators for multi-step flows (registration → verification)

---

## 10. Performance Optimizations

### 10.1 Route-Based Code Splitting

```typescript
// Lazy load route components
const LoginPage = lazy(() => import('@/pages/auth/LoginPage'));
const RegisterPage = lazy(() => import('@/pages/auth/RegisterPage'));
const DashboardPage = lazy(() => import('@/pages/DashboardPage'));

export const routes: RouteObject[] = [
  {
    path: '/login',
    element: (
      <Suspense fallback={<LoadingSpinner />}>
        <LoginPage />
      </Suspense>
    ),
  },
  // ... other routes
];
```

### 10.2 Prefetching

- Prefetch dashboard assets after successful login
- Preload critical auth routes on app load
- Preconnect to API domain

```typescript
// utils/prefetch.ts
export const prefetchDashboard = () => {
  const link = document.createElement('link');
  link.rel = 'prefetch';
  link.href = '/dashboard';
  document.head.appendChild(link);
};

// Call after login success
prefetchDashboard();
```

### 10.3 Navigation Caching

- Cache user data in React Query/SWR
- Stale-while-revalidate strategy
- Optimistic UI updates

```typescript
// hooks/useCurrentUser.ts
import { useQuery } from '@tanstack/react-query';

export const useCurrentUser = () => {
  return useQuery({
    queryKey: ['currentUser'],
    queryFn: api.getCurrentUser,
    staleTime: 5 * 60 * 1000, // 5 minutes
    cacheTime: 30 * 60 * 1000, // 30 minutes
    refetchOnWindowFocus: true,
  });
};
```

---

## 11. Accessibility

### 11.1 Keyboard Navigation

- All interactive elements accessible via Tab
- Skip navigation links
- Focus management on route changes
- Escape key to close modals

```typescript
// hooks/useFocusManagement.ts
export const useFocusManagement = () => {
  const location = useLocation();
  
  useEffect(() => {
    // Focus main content on route change
    const mainContent = document.getElementById('main-content');
    mainContent?.focus();
  }, [location.pathname]);
};
```

### 11.2 Screen Reader Announcements

- Announce route changes
- Announce loading states
- Announce errors

```typescript
// components/RouteAnnouncer.tsx
export const RouteAnnouncer: React.FC = () => {
  const location = useLocation();
  const [announcement, setAnnouncement] = useState('');
  
  useEffect(() => {
    const title = document.title;
    setAnnouncement(`Navigated to ${title}`);
  }, [location.pathname]);
  
  return (
    <div role="status" aria-live="polite" aria-atomic="true" className="sr-only">
      {announcement}
    </div>
  );
};
```

---

## 12. Monitoring & Analytics

### 12.1 Navigation Tracking

```typescript
// utils/analytics.ts
export const trackPageView = (path: string) => {
  analytics.track('Page Viewed', {
    path,
    timestamp: new Date().toISOString(),
    referrer: document.referrer,
  });
};

// Track navigation events
export const trackNavigation = (from: string, to: string, duration: number) => {
  analytics.track('Navigation', {
    from,
    to,
    duration_ms: duration,
  });
};
```

### 12.2 Error Tracking

```typescript
// Setup Sentry for navigation errors
import * as Sentry from '@sentry/react';
import { createBrowserRouter } from 'react-router-dom';

const router = createBrowserRouter(routes);

const SentryRoutes = Sentry.withSentryReactRouterV6Routing(router);
```

---

## 13. Testing Strategy

### 13.1 Route Testing

```typescript
// tests/routes/authRoutes.test.tsx
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { AuthProvider } from '@/contexts/AuthContext';

describe('Auth Routes', () => {
  it('redirects unauthenticated users to login', () => {
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AuthProvider>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );
    
    expect(screen.getByText('Login')).toBeInTheDocument();
  });
  
  it('allows authenticated users to access protected routes', async () => {
    // Mock authenticated state
    const mockAuthContext = {
      isAuthenticated: true,
      user: { id: '1', email: 'test@example.com' },
    };
    
    render(
      <MemoryRouter initialEntries={['/dashboard']}>
        <AuthProvider value={mockAuthContext}>
          <AppRoutes />
        </AuthProvider>
      </MemoryRouter>
    );
    
    expect(await screen.findByText('Dashboard')).toBeInTheDocument();
  });
});
```

### 13.2 Navigation Flow Testing (E2E)

```typescript
// e2e/authFlow.spec.ts (Playwright)
import { test, expect } from '@playwright/test';

test('complete registration and login flow', async ({ page }) => {
  // Navigate to registration
  await page.goto('/register');
  
  // Fill registration form
  await page.fill('[name="email"]', 'newuser@example.com');
  await page.fill('[name="password"]', 'StrongP@ssw0rd');
  await page.check('[name="gdprConsent"]');
  await page.click('button[type="submit"]');
  
  // Verify redirect to verification page
  await expect(page).toHaveURL('/verify-email');
  
  // Mock email verification (click link)
  const verificationToken = 'mock-token-123';
  await page.goto(`/verify-email?token=${verificationToken}`);
  
  // Verify redirect to login
  await expect(page).toHaveURL('/login');
  
  // Login
  await page.fill('[name="email"]', 'newuser@example.com');
  await page.fill('[name="password"]', 'StrongP@ssw0rd');
  await page.click('button[type="submit"]');
  
  // Verify redirect to dashboard
  await expect(page).toHaveURL('/dashboard');
});
```

---

## 14. Documentation References

- **API Documentation**: `/docs/api/authentication.md`
- **Frontend Architecture**: `/docs/frontend/architecture.md`
- **Security Guidelines**: `/docs/security/authentication.md`
- **Mobile Navigation**: `/docs/mobile/navigation.md`
- **Testing Guide**: `/docs/testing/e2e-testing.md`

---

**Document Version**: 1.0
**Last Updated**: 2025-10-29
**Maintained By**: SUMA Finance Engineering Team