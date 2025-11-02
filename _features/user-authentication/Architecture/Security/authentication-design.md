# Authentication Design Architecture

**Project**: User Registration & Authentication
**Feature**: Authentication System
**Domain**: Security
**Generated**: 2025-11-01T00:00:00Z

---

## 1. Authentication Architecture Overview

### Architecture Philosophy
The authentication system follows a **zero-trust security model** with **defense-in-depth** strategy. Every request is authenticated and validated, with multiple layers of security controls to prevent unauthorized access.

**Core Principles:**
- Zero-trust: Never trust, always verify
- Least privilege: Grant minimum required permissions
- Defense-in-depth: Multiple security layers
- Secure by default: Security-first design
- Fail securely: Graceful degradation without exposing vulnerabilities

### Authentication Flows

#### Login Flow
```
1. User submits credentials (email/password)
2. Rate limiting check (IP and account level)
3. CAPTCHA verification (if triggered)
4. Retrieve user from database
5. Verify password hash (constant-time comparison)
6. Check MFA requirement
7. If MFA enabled: Request MFA code
8. Validate MFA code
9. Generate session token + refresh token
10. Create session record in database
11. Set secure HTTP-only cookies
12. Return success response with user data
```

#### Logout Flow
```
1. Extract session token from request
2. Validate token signature
3. Delete session from session store
4. Add token to revocation list (if JWT)
5. Clear authentication cookies
6. Return success response
```

#### Session Refresh Flow
```
1. Extract refresh token from request
2. Validate refresh token signature
3. Check token not revoked
4. Verify token not expired
5. Generate new access token
6. Generate new refresh token (rotation)
7. Revoke old refresh token
8. Return new tokens
```

#### Password Reset Flow
```
1. User requests password reset (email)
2. Rate limiting check (3 requests/hour)
3. Verify user exists (generic response)
4. Generate cryptographically secure reset token
5. Hash token and store with expiration (1 hour)
6. Send email with reset link
7. User clicks link with token
8. Validate token (not used, not expired)
9. User submits new password
10. Validate password policy
11. Hash new password
12. Update user record
13. Mark token as used
14. Invalidate all user sessions
15. Send confirmation email
```

### Component Diagram

```
┌─────────────────┐
│   Frontend      │
│   (React/Vue)   │
└────────┬────────┘
         │ HTTPS
         ▼
┌─────────────────────────────────────────┐
│       API Gateway / Load Balancer        │
│  - Rate Limiting                         │
│  - DDoS Protection                       │
│  - SSL/TLS Termination                   │
└─────────────────┬───────────────────────┘
                  │
         ┌────────┴────────┐
         ▼                 ▼
┌──────────────────┐ ┌──────────────────┐
│ Auth Service     │ │ API Services     │
│ - Login          │ │ - Protected      │
│ - Register       │ │   Endpoints      │
│ - MFA            │ │ - Auth Middleware│
│ - Password Reset │ │                  │
└────────┬─────────┘ └────────┬─────────┘
         │                    │
    ┌────┴────────────────────┴────┐
    ▼                              ▼
┌─────────────┐            ┌──────────────┐
│   Redis     │            │  PostgreSQL  │
│  - Sessions │            │  - Users     │
│  - Cache    │            │  - Sessions  │
│  - Rate     │            │  - Tokens    │
│    Limits   │            │  - Audit Log │
└─────────────┘            └──────────────┘
         │
         ▼
┌─────────────────┐
│ External IdPs   │
│ - Google OAuth  │
│ - SAML Provider │
│ - Azure AD      │
└─────────────────┘
```

### Integration Points

**Frontend Integration:**
- Authentication state management (Redux/Context)
- Protected route guards
- Token storage and refresh
- Login/register UI components
- Session timeout handling

**Backend API Integration:**
- Authentication middleware
- JWT validation
- Role-based authorization
- Resource ownership checks
- Audit logging

**Database Integration:**
- User account management
- Session persistence
- Token storage
- Audit log recording
- Password history tracking

**External Identity Providers:**
- OAuth 2.0 / OpenID Connect flow
- SAML 2.0 integration
- Social login (Google, Apple, Microsoft)
- Enterprise SSO (Azure AD, Okta)

### Technology Stack

**Authentication Libraries:**
- **Backend**: Passport.js (Node.js), Spring Security (Java), Django Auth (Python)
- **JWT**: jsonwebtoken (Node.js), jose (browser), PyJWT (Python)
- **Password Hashing**: bcrypt, argon2, scrypt
- **OAuth/SAML**: passport-oauth2, passport-saml, node-saml

**Session Management:**
- **Session Store**: Redis (primary), Memcached (fallback)
- **Session Library**: express-session, connect-redis, iron-session

**Security Libraries:**
- **CSRF**: csurf, csrf-sync
- **Rate Limiting**: express-rate-limit, rate-limiter-flexible
- **Helmet**: Security headers middleware
- **CAPTCHA**: google-recaptcha, hcaptcha

**Protocols & Standards:**
- OAuth 2.0 / OpenID Connect
- SAML 2.0
- JWT (RFC 7519)
- TOTP (RFC 6238)
- WebAuthn / FIDO2

---

## 2. Authentication Methods Design

### Primary Authentication

#### Email/Password Authentication

**Implementation Approach:**
- Email as unique identifier
- Email verification required before account activation
- Password stored as hash (Argon2id or bcrypt)
- Password complexity enforced on client and server

**Password Validation Rules:**
```javascript
const passwordPolicy = {
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  preventCommonPasswords: true,
  preventBreachedPasswords: true,
  preventPasswordReuse: 5 // Last 5 passwords
};
```

**Email Verification Flow:**
```
1. User registers with email + password
2. Generate verification token (256-bit random)
3. Hash token and store with expiration (24 hours)
4. Send verification email with link
5. User clicks link
6. Validate token (not expired, not used)
7. Mark email as verified
8. Mark token as used
9. Redirect to login or auto-login
```

#### Username/Password Authentication

**Implementation Approach:**
- Username as unique identifier
- Username constraints: 3-30 characters, alphanumeric + underscore
- Case-insensitive username lookup
- Username cannot be changed after creation

**Username Validation:**
```javascript
const usernamePolicy = {
  minLength: 3,
  maxLength: 30,
  pattern: /^[a-zA-Z0-9_]+$/,
  caseSensitive: false,
  preventReservedWords: ['admin', 'root', 'system', 'api', 'support'],
  preventProfanity: true
};
```

#### Phone Number Authentication

**Implementation Approach:**
- Phone number in E.164 format (+country_code + number)
- SMS verification via Twilio, AWS SNS, or Vonage
- Phone number as secondary or primary identifier

**SMS Verification Flow:**
```
1. User enters phone number
2. Validate phone number format (E.164)
3. Rate limit check (3 SMS per phone per hour)
4. Generate 6-digit OTP code
5. Store hashed code with expiration (10 minutes)
6. Send SMS via gateway
7. User enters code
8. Validate code (constant-time comparison)
9. Mark phone as verified
10. Limit attempts (5 max, then lockout)
```

**Carrier Integration:**
- Primary: Twilio (SMS API)
- Fallback: AWS SNS, Vonage
- Delivery tracking via webhooks
- Retry logic for failed deliveries

#### Magic Link Authentication

**Implementation Approach:**
- Passwordless login via email link
- Secure token embedded in link
- One-time use token with short expiration

**Magic Link Flow:**
```
1. User enters email
2. Rate limit check (5 requests per hour)
3. Generate secure token (256-bit random)
4. Hash token and store with expiration (15 minutes)
5. Send email with link containing token
6. User clicks link
7. Validate token (not expired, not used)
8. Mark token as used
9. Create session and log user in
10. Redirect to application
```

**Token Generation:**
```javascript
const crypto = require('crypto');

function generateMagicLinkToken() {
  // 256-bit cryptographically secure random token
  return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
```

---

### Multi-Factor Authentication (MFA)

#### TOTP (Time-based One-Time Password)

**Implementation Approach:**
- RFC 6238 compliant TOTP generation
- 30-second time step
- 6-digit codes
- QR code for authenticator app enrollment

**Enrollment Flow:**
```
1. User requests MFA enrollment
2. Generate secret key (base32 encoded, 160-bit)
3. Generate QR code with otpauth:// URI
4. Display QR code to user
5. User scans with authenticator app (Google Authenticator, Authy)
6. User enters verification code
7. Validate code (allow ±1 time step for clock skew)
8. Store encrypted secret in database
9. Generate backup codes (10x 8-digit codes)
10. Mark MFA as enabled
```

**TOTP Validation:**
```javascript
const speakeasy = require('speakeasy');

function verifyTOTP(secret, token) {
  return speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: token,
    window: 1 // Allow ±1 time step (30 seconds)
  });
}
```

**QR Code Generation:**
```javascript
const QRCode = require('qrcode');

async function generateQRCode(secret, email) {
  const otpauthURL = speakeasy.otpauthURL({
    secret: secret,
    label: email,
    issuer: 'FinanceApp',
    encoding: 'base32'
  });
  
  return await QRCode.toDataURL(otpauthURL);
}
```

#### SMS OTP

**Implementation Approach:**
- 6-digit numeric code
- 10-minute expiration
- SMS via Twilio/AWS SNS
- Rate limiting: 3 SMS per 10 minutes

**SMS Gateway Integration:**
```javascript
const twilio = require('twilio');
const client = twilio(accountSid, authToken);

async function sendSMSOTP(phoneNumber, code) {
  await client.messages.create({
    body: `Your verification code is: ${code}. Valid for 10 minutes.`,
    to: phoneNumber,
    from: twilioPhoneNumber
  });
}
```

**Retry Logic:**
```javascript
async function sendOTPWithRetry(phoneNumber, code, maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      await sendSMSOTP(phoneNumber, code);
      return { success: true };
    } catch (error) {
      if (attempt === maxRetries) {
        return { success: false, error: 'SMS delivery failed' };
      }
      await sleep(1000 * attempt); // Exponential backoff
    }
  }
}
```

#### Email OTP

**Implementation Approach:**
- 6-digit alphanumeric code
- 15-minute expiration
- HTML email template
- Rate limiting: 5 emails per hour

**Email Template:**
```html
<!DOCTYPE html>
<html>
<head>
  <style>
    .code { font-size: 32px; font-weight: bold; letter-spacing: 5px; }
  </style>
</head>
<body>
  <h2>Your Verification Code</h2>
  <p>Enter this code to verify your identity:</p>
  <div class="code">{{code}}</div>
  <p>This code expires in 15 minutes.</p>
  <p>If you didn't request this code, please ignore this email.</p>
</body>
</html>
```

**Delivery Verification:**
- Track email delivery via SendGrid/AWS SES webhooks
- Retry failed deliveries with exponential backoff
- Log delivery status for audit

#### Biometric Authentication

**Implementation Approach:**
- Native biometric APIs (Face ID, Touch ID, Windows Hello)
- WebAuthn for browser-based biometric
- Fallback to PIN/password if biometric unavailable

**Face ID / Touch ID (iOS):**
```swift
import LocalAuthentication

func authenticateWithBiometric() {
    let context = LAContext()
    var error: NSError?
    
    if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, 
                               localizedReason: "Authenticate to access your account") { success, error in
            if success {
                // Biometric authentication succeeded
            } else {
                // Fallback to password
            }
        }
    }
}
```

**Windows Hello Integration:**
```csharp
using Windows.Security.Credentials.UI;

public async Task<bool> AuthenticateWithWindowsHello() {
    var result = await UserConsentVerifier.RequestVerificationAsync("Authenticate to access your account");
    return result == UserConsentVerificationResult.Verified;
}
```

#### Hardware Tokens (FIDO2 / WebAuthn)

**Implementation Approach:**
- FIDO2 / WebAuthn standard
- Support for YubiKey, Titan Security Key
- Browser-based registration and authentication
- Server-side credential validation

**Registration Flow:**
```javascript
// Client-side
const publicKeyCredentialCreationOptions = {
  challenge: new Uint8Array(32), // From server
  rp: { name: "FinanceApp", id: "example.com" },
  user: {
    id: new Uint8Array(16),
    name: "user@example.com",
    displayName: "User Name"
  },
  pubKeyCredParams: [{ alg: -7, type: "public-key" }],
  authenticatorSelection: {
    authenticatorAttachment: "cross-platform",
    requireResidentKey: false,
    userVerification: "preferred"
  },
  timeout: 60000,
  attestation: "direct"
};

const credential = await navigator.credentials.create({
  publicKey: publicKeyCredentialCreationOptions
});

// Send credential.response to server for storage
```

**Authentication Flow:**
```javascript
// Client-side
const publicKeyCredentialRequestOptions = {
  challenge: new Uint8Array(32), // From server
  allowCredentials: [{
    id: credentialId,
    type: 'public-key',
    transports: ['usb', 'nfc', 'ble']
  }],
  timeout: 60000,
  userVerification: "preferred"
};

const assertion = await navigator.credentials.get({
  publicKey: publicKeyCredentialRequestOptions
});

// Send assertion.response to server for verification
```

---

### Social Authentication (OAuth 2.0)

#### Google Sign-In

**OAuth 2.0 Configuration:**
- Client ID: From Google Cloud Console
- Client Secret: Stored in environment variables
- Redirect URI: `https://app.example.com/auth/google/callback`
- Scopes: `openid`, `email`, `profile`

**Implementation Flow:**
```javascript
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "/auth/google/callback"
  },
  async (accessToken, refreshToken, profile, done) => {
    // Find or create user based on Google profile
    let user = await User.findOne({ googleId: profile.id });
    
    if (!user) {
      user = await User.create({
        googleId: profile.id,
        email: profile.emails[0].value,
        name: profile.displayName,
        emailVerified: true // Google verifies email
      });
    }
    
    return done(null, user);
  }
));

// Routes
app.get('/auth/google', passport.authenticate('google', { scope: ['openid', 'email', 'profile'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
  // Generate session token
  // Redirect to application
});
```

#### Apple Sign-In

**Configuration:**
- App ID: From Apple Developer Portal
- Team ID, Key ID, Private Key (P8 file)
- Redirect URI: `https://app.example.com/auth/apple/callback`
- Scopes: `name`, `email`

**Privacy Considerations:**
- Apple provides "Hide My Email" feature (relay email)
- User may change email relay at any time
- Store Apple user ID as primary identifier

**Implementation:**
```javascript
const AppleStrategy = require('passport-apple').Strategy;

passport.use(new AppleStrategy({
    clientID: process.env.APPLE_CLIENT_ID,
    teamID: process.env.APPLE_TEAM_ID,
    keyID: process.env.APPLE_KEY_ID,
    privateKeyLocation: './AuthKey.p8',
    callbackURL: '/auth/apple/callback',
    passReqToCallback: true
  },
  async (req, accessToken, refreshToken, idToken, profile, done) => {
    // Apple only sends user info on first authorization
    const userInfo = req.body.user ? JSON.parse(req.body.user) : null;
    
    let user = await User.findOne({ appleId: profile.id });
    
    if (!user) {
      user = await User.create({
        appleId: profile.id,
        email: profile.email, // May be relay email
        name: userInfo ? `${userInfo.name.firstName} ${userInfo.name.lastName}` : null,
        emailVerified: true
      });
    }
    
    return done(null, user);
  }
));
```

#### Facebook Login

**Configuration:**
- App ID, App Secret: From Facebook Developers
- Redirect URI: `https://app.example.com/auth/facebook/callback`
- Permissions: `email`, `public_profile`

**Implementation:**
```javascript
const FacebookStrategy = require('passport-facebook').Strategy;

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: '/auth/facebook/callback',
    profileFields: ['id', 'emails', 'name', 'picture']
  },
  async (accessToken, refreshToken, profile, done) => {
    let user = await User.findOne({ facebookId: profile.id });
    
    if (!user) {
      user = await User.create({
        facebookId: profile.id,
        email: profile.emails[0].value,
        name: `${profile.name.givenName} ${profile.name.familyName}`,
        emailVerified: true
      });
    }
    
    return done(null, user);
  }
));
```

#### Microsoft / Azure AD

**Configuration:**
- Application ID: From Azure Portal
- Tenant ID: Organization tenant or "common" for multi-tenant
- Client Secret: From Azure Portal
- Redirect URI: `https://app.example.com/auth/microsoft/callback`

**Implementation:**
```javascript
const OIDCStrategy = require('passport-azure-ad').OIDCStrategy;

passport.use(new OIDCStrategy({
    identityMetadata: `https://login.microsoftonline.com/${tenantID}/v2.0/.well-known/openid-configuration`,
    clientID: process.env.MICROSOFT_CLIENT_ID,
    clientSecret: process.env.MICROSOFT_CLIENT_SECRET,
    responseType: 'code',
    responseMode: 'form_post',
    redirectUrl: '/auth/microsoft/callback',
    allowHttpForRedirectUrl: false,
    scope: ['openid', 'profile', 'email']
  },
  async (iss, sub, profile, accessToken, refreshToken, done) => {
    let user = await User.findOne({ microsoftId: profile.oid });
    
    if (!user) {
      user = await User.create({
        microsoftId: profile.oid,
        email: profile._json.email,
        name: profile.displayName,
        emailVerified: true
      });
    }
    
    return done(null, user);
  }
));
```

---

### Enterprise Authentication

#### SAML 2.0

**Service Provider Configuration:**
```javascript
const saml2 = require('saml2-js');

const sp = new saml2.ServiceProvider({
  entity_id: "https://app.example.com/metadata.xml",
  private_key: fs.readFileSync("./certs/sp-key.pem").toString(),
  certificate: fs.readFileSync("./certs/sp-cert.pem").toString(),
  assert_endpoint: "https://app.example.com/auth/saml/assert",
  allow_unencrypted_assertion: false
});

const idp = new saml2.IdentityProvider({
  sso_login_url: "https://idp.example.com/sso/saml",
  sso_logout_url: "https://idp.example.com/slo/saml",
  certificates: [fs.readFileSync("./certs/idp-cert.pem").toString()]
});
```

**SSO Login Flow:**
```javascript
// Initiate SSO
app.get('/auth/saml/login', (req, res) => {
  sp.create_login_request_url(idp, {}, (err, login_url, request_id) => {
    if (err) return res.status(500).send(err);
    res.redirect(login_url);
  });
});

// Assertion endpoint
app.post('/auth/saml/assert', (req, res) => {
  const options = { request_body: req.body };
  
  sp.post_assert(idp, options, async (err, saml_response) => {
    if (err) return res.status(500).send(err);
    
    // Extract user attributes
    const email = saml_response.user.email;
    const name = saml_response.user.name;
    const groups = saml_response.user.groups;
    
    // Find or create user
    let user = await User.findOne({ email });
    if (!user) {
      user = await User.create({ email, name, emailVerified: true });
    }
    
    // Sync groups/roles
    await syncUserRoles(user, groups);
    
    // Create session
    const sessionToken = generateSessionToken(user);
    res.cookie('session', sessionToken, { httpOnly: true, secure: true });
    res.redirect('/dashboard');
  });
});
```

**IdP Integration:**
- Okta: Import metadata XML from Okta admin console
- Azure AD: Configure enterprise application in Azure Portal
- OneLogin: Set up SAML connector in OneLogin admin
- Custom IdP: Exchange metadata XML files

#### OAuth 2.0 (Client Credentials)

**Authorization Server Configuration:**
```javascript
const oauth2orize = require('oauth2orize');
const server = oauth2orize.createServer();

// Client credentials grant
server.exchange(oauth2orize.exchange.clientCredentials((client, scope, done) => {
  const token = generateAccessToken(client, scope);
  return done(null, token);
}));

// Token endpoint
app.post('/oauth/token',
  passport.authenticate('oauth2-client-password', { session: false }),
  server.token(),
  server.errorHandler()
);
```

**Client Registration:**
```sql
CREATE TABLE oauth_clients (
  id UUID PRIMARY KEY,
  client_id VARCHAR(255) UNIQUE NOT NULL,
  client_secret_hash VARCHAR(255) NOT NULL,
  name VARCHAR(255) NOT NULL,
  redirect_uris TEXT[],
  allowed_scopes TEXT[],
  created_at TIMESTAMP DEFAULT NOW()
);
```

#### OpenID Connect

**Discovery Endpoint:**
```javascript
app.get('/.well-known/openid-configuration', (req, res) => {
  res.json({
    issuer: 'https://app.example.com',
    authorization_endpoint: 'https://app.example.com/oauth/authorize',
    token_endpoint: 'https://app.example.com/oauth/token',
    userinfo_endpoint: 'https://app.example.com/oauth/userinfo',
    jwks_uri: 'https://app.example.com/.well-known/jwks.json',
    response_types_supported: ['code', 'token', 'id_token'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    scopes_supported: ['openid', 'profile', 'email']
  });
});
```

**Claims Mapping:**
```javascript
function buildIDToken(user, scope) {
  const claims = {
    iss: 'https://app.example.com',
    sub: user.id,
    aud: clientId,
    exp: Math.floor(Date.now() / 1000) + 3600,
    iat: Math.floor(Date.now() / 1000)
  };
  
  if (scope.includes('profile')) {
    claims.name = user.name;
    claims.given_name = user.firstName;
    claims.family_name = user.lastName;
  }
  
  if (scope.includes('email')) {
    claims.email = user.email;
    claims.email_verified = user.emailVerified;
  }
  
  return jwt.sign(claims, privateKey, { algorithm: 'RS256' });
}
```

#### LDAP / Active Directory

**Connection Configuration:**
```javascript
const ldap = require('ldapjs');

const client = ldap.createClient({
  url: ['ldap://dc1.example.com:389', 'ldap://dc2.example.com:389'],
  reconnect: true,
  timeout: 5000,
  connectTimeout: 10000,
  idleTimeout: 30000
});

// Bind with service account
client.bind('cn=serviceaccount,dc=example,dc=com', serviceAccountPassword, (err) => {
  if (err) console.error('LDAP bind failed:', err);
});
```

**User Authentication:**
```javascript
async function authenticateLDAP(username, password) {
  return new Promise((resolve, reject) => {
    // Search for user
    const searchOptions = {
      scope: 'sub',
      filter: `(sAMAccountName=${username})`,
      attributes: ['dn', 'mail', 'displayName', 'memberOf']
    };
    
    client.search('dc=example,dc=com', searchOptions, (err, res) => {
      if (err) return reject(err);
      
      let userDN = null;
      let userData = null;
      
      res.on('searchEntry', (entry) => {
        userDN = entry.objectName;
        userData = {
          email: entry.object.mail,
          name: entry.object.displayName,
          groups: entry.object.memberOf
        };
      });
      
      res.on('end', () => {
        if (!userDN) return reject(new Error('User not found'));
        
        // Authenticate with user credentials
        const userClient = ldap.createClient({ url: 'ldap://dc1.example.com:389' });
        userClient.bind(userDN, password, (err) => {
          if (err) return reject(new Error('Invalid credentials'));
          resolve(userData);
        });
      });
    });
  });
}
```

**Group Membership Sync:**
```javascript
async function syncLDAPGroups(user, ldapGroups) {
  // Map LDAP groups to application roles
  const roleMapping = {
    'CN=Finance-Admins,OU=Groups,DC=example,DC=com': 'admin',
    'CN=Finance-Users,OU=Groups,DC=example,DC=com': 'user',
    'CN=Finance-Managers,OU=Groups,DC=example,DC=com': 'manager'
  };
  
  const roles = ldapGroups
    .map(group => roleMapping[group])
    .filter(role => role);
  
  await User.update({ id: user.id }, { roles });
}
```

---

## 3. Password Security Architecture

### Password Policy Engine

**Policy Configuration:**
```javascript
const passwordPolicy = {
  minLength: 12,
  maxLength: 128,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSpecialChars: true,
  specialChars: '!@#$%^&*()_+-=[]{}|;:,.<>?',
  preventCommonPasswords: true,
  preventBreachedPasswords: true,
  preventPasswordReuse: 5,
  maxPasswordAge: 90, // days
  preventUsernameInPassword: true,
  preventEmailInPassword: true
};
```

**Password Validation Function:**
```javascript
const zxcvbn = require('zxcvbn');

async function validatePassword(password, user) {
  const errors = [];
  
  // Length check
  if (password.length < passwordPolicy.minLength) {
    errors.push(`Password must be at least ${passwordPolicy.minLength} characters`);
  }
  if (password.length > passwordPolicy.maxLength) {
    errors.push(`Password must not exceed ${passwordPolicy.maxLength} characters`);
  }
  
  // Complexity checks
  if (passwordPolicy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (passwordPolicy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (passwordPolicy.requireNumbers && !/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  if (passwordPolicy.requireSpecialChars && !new RegExp(`[${passwordPolicy.specialChars}]`).test(password)) {
    errors.push('Password must contain at least one special character');
  }
  
  // Dictionary check
  if (passwordPolicy.preventCommonPasswords) {
    const strength = zxcvbn(password, [user.email, user.username, user.name]);
    if (strength.score < 3) {
      errors.push('Password is too common or weak');
    }
  }
  
  // Breach check
  if (passwordPolicy.preventBreachedPasswords) {
    const breached = await checkPasswordBreach(password);
    if (breached) {
      errors.push('Password has been found in a data breach');
    }
  }
  
  // Username/email check
  if (passwordPolicy.preventUsernameInPassword && user.username && password.toLowerCase().includes(user.username.toLowerCase())) {
    errors.push('Password must not contain your username');
  }
  if (passwordPolicy.preventEmailInPassword && user.email && password.toLowerCase().includes(user.email.split('@')[0].toLowerCase())) {
    errors.push('Password must not contain your email');
  }
  
  // Password history check
  if (passwordPolicy.preventPasswordReuse > 0) {
    const passwordHistory = await PasswordHistory.find({ userId: user.id }).limit(passwordPolicy.preventPasswordReuse);
    for (const historic of passwordHistory) {
      if (await verifyPassword(password, historic.passwordHash)) {
        errors.push(`Password must not match any of your last ${passwordPolicy.preventPasswordReuse} passwords`);
        break;
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors
  };
}
```

**Common Password Blacklist:**
```javascript
// Load from file or database
const commonPasswords = new Set([
  'password', 'Password123', '123456', 'qwerty', 'admin',
  'letmein', 'welcome', 'monkey', 'dragon', 'master',
  // ... 10,000+ common passwords
]);

function isCommonPassword(password) {
  return commonPasswords.has(password.toLowerCase());
}
```

**Breach Check Integration (HaveIBeenPwned API):**
```javascript
const crypto = require('crypto');
const axios = require('axios');

async function checkPasswordBreach(password) {
  // Hash password with SHA-1
  const hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = hash.substring(0, 5);
  const suffix = hash.substring(5);
  
  try {
    // Query HaveIBeenPwned API (k-anonymity)
    const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { 'Add-Padding': 'true' }
    });
    
    // Check if suffix appears in results
    const hashes = response.data.split('\n');
    for (const line of hashes) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix === suffix) {
        return parseInt(count, 10); // Return breach count
      }
    }
    
    return 0; // Not breached
  } catch (error) {
    console.error('Breach check failed:', error);
    return 0; // Fail open
  }
}
```

### Password Hashing Strategy

**Argon2id Implementation (Recommended):**
```javascript
const argon2 = require('argon2');

const hashingConfig = {
  type: argon2.argon2id, // Hybrid mode
  memoryCost: 65536, // 64 MB
  timeCost: 3, // 3 iterations
  parallelism: 4 // 4 threads
};

async function hashPassword(password) {
  return await argon2.hash(password, hashingConfig);
}

async function verifyPassword(password, hash) {
  try {
    return await argon2.verify(hash, password);
  } catch (error) {
    return false;
  }
}
```

**bcrypt Implementation (Alternative):**
```javascript
const bcrypt = require('bcrypt');

const SALT_ROUNDS = 12;

async function hashPassword(password) {
  return await bcrypt.hash(password, SALT_ROUNDS);
}

async function verifyPassword(password, hash) {
  return await bcrypt.compare(password, hash);
}
```

**Pepper Strategy:**
```javascript
const crypto = require('crypto');

// Store pepper in environment variable
const PEPPER = process.env.PASSWORD_PEPPER;

function addPepper(password) {
  return crypto.createHmac('sha256', PEPPER).update(password).digest('hex') + password;
}

async function hashPasswordWithPepper(password) {
  const pepperedPassword = addPepper(password);
  return await argon2.hash(pepperedPassword, hashingConfig);
}

async function verifyPasswordWithPepper(password, hash) {
  const pepperedPassword = addPepper(password);
  return await argon2.verify(hash, pepperedPassword);
}
```

**Hash Migration Strategy:**
```javascript
async function migratePasswordHash(user, plainPassword) {
  // Check if using legacy hash algorithm
  if (user.passwordHash.startsWith('$2b$')) {
    // Legacy bcrypt hash
    const isValid = await bcrypt.compare(plainPassword, user.passwordHash);
    if (isValid) {
      // Upgrade to Argon2id
      const newHash = await argon2.hash(plainPassword, hashingConfig);
      await User.update({ id: user.id }, { passwordHash: newHash });
    }
    return isValid;
  } else {
    // Current Argon2id hash
    return await argon2.verify(user.passwordHash, plainPassword);
  }
}
```

**Salt Generation:**
```javascript
// Argon2 and bcrypt automatically generate salts
// Manual salt generation for custom implementations:
const crypto = require('crypto');

function generateSalt(length = 16) {
  return crypto.randomBytes(length).toString('hex');
}

function hashWithSalt(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}
```

### Password Reset Flow

**Token Generation:**
```javascript
const crypto = require('crypto');

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}
```

**Request Password Reset:**
```javascript
async function requestPasswordReset(email) {
  // Rate limiting check
  const recentAttempts = await PasswordResetAttempt.count({
    email,
    createdAt: { $gte: new Date(Date.now() - 60 * 60 * 1000) }
  });
  
  if (recentAttempts >= 3) {
    throw new Error('Too many password reset requests. Please try again later.');
  }
  
  // Find user (don't reveal if user exists)
  const user = await User.findOne({ email });
  
  // Log attempt
  await PasswordResetAttempt.create({ email, ipAddress: req.ip });
  
  if (!user) {
    // Generic response (prevent user enumeration)
    return { message: 'If an account exists with this email, a password reset link will be sent.' };
  }
  
  // Generate reset token
  const token = generateResetToken();
  const tokenHash = hashResetToken(token);
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour
  
  // Store token
  await PasswordResetToken.create({
    userId: user.id,
    tokenHash,
    expiresAt,
    used: false
  });
  
  // Send email
  const resetLink = `https://app.example.com/reset-password?token=${token}`;
  await sendPasswordResetEmail(user.email, resetLink);
  
  return { message: 'If an account exists with this email, a password reset link will be sent.' };
}
```

**Complete Password Reset:**
```javascript
async function resetPassword(token, newPassword) {
  // Hash token
  const tokenHash = hashResetToken(token);
  
  // Find token
  const resetToken = await PasswordResetToken.findOne({
    tokenHash,
    used: false,
    expiresAt: { $gte: new Date() }
  });
  
  if (!resetToken) {
    throw new Error('Invalid or expired password reset token');
  }
  
  // Load user
  const user = await User.findById(resetToken.userId);
  
  // Validate new password
  const validation = await validatePassword(newPassword, user);
  if (!validation.valid) {
    throw new Error(validation.errors.join(', '));
  }
  
  // Hash new password
  const passwordHash = await hashPassword(newPassword);
  
  // Update user
  await User.update({ id: user.id }, { 
    passwordHash,
    passwordChangedAt: new Date()
  });
  
  // Add to password history
  await PasswordHistory.create({
    userId: user.id,
    passwordHash
  });
  
  // Mark token as used
  await PasswordResetToken.update({ id: resetToken.id }, { used: true });
  
  // Invalidate all sessions
  await Session.delete({ userId: user.id });
  
  // Send confirmation email
  await sendPasswordChangedEmail(user.email);
  
  // Audit log
  await AuditLog.create({
    userId: user.id,
    eventType: 'PASSWORD_RESET',
    ipAddress: req.ip,
    userAgent: req.headers['user-agent']
  });
  
  return { message: 'Password successfully reset' };
}
```

**Rate Limiting:**
```javascript
const rateLimit = require('express-rate-limit');

const passwordResetLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 requests per hour
  message: 'Too many password reset requests. Please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.body.email || req.ip;
  }
});

app.post('/auth/forgot-password', passwordResetLimiter, async (req, res) => {
  // Handler
});
```

**Session Invalidation:**
```javascript
async function invalidateAllUserSessions(userId) {
  // Delete sessions from database
  await Session.delete({ userId });
  
  // Delete sessions from Redis
  const sessionKeys = await redis.keys(`session:${userId}:*`);
  if (sessionKeys.length > 0) {
    await redis.del(...sessionKeys);
  }
  
  // Add user ID to revocation list (for JWT)
  await redis.setex(`user:${userId}:revoked`, 86400, Date.now());
}
```

---

## 4. Session Management Architecture

### Session Storage

**Redis Session Store Configuration:**
```javascript
const redis = require('redis');
const session = require('express-session');
const RedisStore = require('connect-redis')(session);

const redisClient = redis.createClient({
  host: process.env.REDIS_HOST,
  port: process.env.REDIS_PORT,
  password: process.env.REDIS_PASSWORD,
  db: 0,
  retry_strategy: (options) => {
    if (options.error && options.error.code === 'ECONNREFUSED') {
      return new Error('Redis connection refused');
    }
    if (options.total_retry_time > 1000 * 60 * 60) {
      return new Error('Redis retry time exhausted');
    }
    if (options.attempt > 10) {
      return undefined;
    }
    return Math.min(options.attempt * 100, 3000);
  }
});

const sessionStore = new RedisStore({
  client: redisClient,
  prefix: 'session:',
  ttl: 86400 // 24 hours
});

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: true,
    httpOnly: true,
    sameSite: 'strict',
    maxAge: 86400000 // 24 hours
  }
}));
```

**Session Data Structure:**
```javascript
const sessionData = {
  userId: 'uuid',
  username: 'user@example.com',
  roles: ['user', 'manager'],
  permissions: ['read:transactions', 'write:transactions'],
  deviceFingerprint: 'hash',
  ipAddress: '192.168.1.1',
  userAgent: 'Mozilla/5.0...',
  createdAt: '2025-11-01T00:00:00Z',
  lastActivity: '2025-11-01T00:30:00Z',
  mfaVerified: true
};
```

**Session Encryption:**
```javascript
const crypto = require('crypto');

const ENCRYPTION_KEY = Buffer.from(process.env.SESSION_ENCRYPTION_KEY, 'hex');
const IV_LENGTH = 16;

function encryptSessionData(data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptSessionData(encryptedData) {
  const parts = encryptedData.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encrypted = parts.join(':');
  const decipher = crypto.createDecipheriv('aes-256-cbc', ENCRYPTION_KEY, iv);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return JSON.parse(decrypted);
}
```

**Session Replication (Multi-Region):**
```javascript
const Redis = require('ioredis');

// Master-replica setup
const masterClient = new Redis({
  host: 'redis-master.example.com',
  port: 6379,
  password: process.env.REDIS_PASSWORD
});

const replicaClient = new Redis({
  host: 'redis-replica.example.com',
  port: 6379,
  password: process.env.REDIS_PASSWORD,
  readOnly: true
});

// Write to master
async function saveSession(sessionId, data) {
  await masterClient.setex(`session:${sessionId}`, 86400, JSON.stringify(data));
}

// Read from replica
async function getSession(sessionId) {
  const data = await replicaClient.get(`session:${sessionId}`);
  return data ? JSON.parse(data) : null;
}
```

### Session Token Design

**JWT Structure:**
```javascript
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Load RSA keys for signing
const privateKey = fs.readFileSync('./keys/private.pem', 'utf8');
const publicKey = fs.readFileSync('./keys/public.pem', 'utf8');

function generateJWT(user) {
  const payload = {
    sub: user.id, // Subject (user ID)
    email: user.email,
    roles: user.roles,
    permissions: user.permissions,
    iat: Math.floor(Date.now() / 1000), // Issued at
    exp: Math.floor(Date.now() / 1000) + (30 * 60), // Expires in 30 minutes
    iss: 'https://app.example.com', // Issuer
    aud: 'https://app.example.com' // Audience
  };
  
  return jwt.sign(payload, privateKey, { algorithm: 'RS256' });
}

function verifyJWT(token) {
  try {
    return jwt.verify(token, publicKey, { 
      algorithms: ['RS256'],
      issuer: 'https://app.example.com',
      audience: 'https://app.example.com'
    });
  } catch (error) {
    return null;
  }
}
```

**Opaque Token Design:**
```javascript
const crypto = require('crypto');

function generateOpaqueToken() {
  return crypto.randomBytes(32).toString('hex');
}

async function createOpaqueSession(user) {
  const token = generateOpaqueToken();
  const sessionData = {
    userId: user.id,
    email: user.email,
    roles: user.roles,
    permissions: user.permissions,
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + 30 * 60 * 1000)
  };
  
  // Store in Redis
  await redis.setex(`session:${token}`, 1800, JSON.stringify(sessionData));
  
  return token;
}

async function validateOpaqueToken(token) {
  const data = await redis.get(`session:${token}`);
  if (!data) return null;
  
  const sessionData = JSON.parse(data);
  if (new Date(sessionData.expiresAt) < new Date()) {
    await redis.del(`session:${token}`);
    return null;
  }
  
  return sessionData;
}
```

**Token Rotation:**
```javascript
async function rotateTokens(refreshToken) {
  // Validate refresh token
  const session = await RefreshToken.findOne({
    tokenHash: hashToken(refreshToken),
    revoked: false,
    expiresAt: { $gte: new Date() }
  });
  
  if (!session) {
    throw new Error('Invalid refresh token');
  }
  
  // Load user
  const user = await User.findById(session.userId);
  
  // Generate new access token
  const newAccessToken = generateJWT(user);
  
  // Generate new refresh token
  const newRefreshToken = generateOpaqueToken();
  const newRefreshTokenHash = hashToken(newRefreshToken);
  
  // Store new refresh token
  await RefreshToken.create({
    userId: user.id,
    tokenHash: newRefreshTokenHash,
    expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
    deviceFingerprint: session.deviceFingerprint
  });
  
  // Revoke old refresh token
  await RefreshToken.update({ id: session.id }, { revoked: true });
  
  return {
    accessToken: newAccessToken,
    refreshToken: newRefreshToken
  };
}
```

### Session Lifecycle

**Session Creation:**
```javascript
async function createSession(user, req) {
  // Generate tokens
  const accessToken = generateJWT(user);
  const refreshToken = generateOpaqueToken();
  
  // Device fingerprint
  const deviceFingerprint = generateDeviceFingerprint(req);
  
  // Store session in database
  const session = await Session.create({
    userId: user.id,
    tokenHash: hashToken(refreshToken),
    deviceFingerprint,
    ipAddress: req.ip,
    userAgent: req.headers['user-agent'],
    expiresAt: new Date(Date.now() + 8 * 60 * 60 * 1000), // 8 hours
    lastActivity: new Date()
  });
  
  // Store in Redis for fast lookup
  await redis.setex(`session:${session.id}`, 28800, JSON.stringify({
    userId: user.id,
    accessToken,
    deviceFingerprint,
    ipAddress: req.ip
  }));
  
  return {
    accessToken,
    refreshToken,
    expiresIn: 1800 // 30 minutes
  };
}
```

**Session Validation:**
```javascript
async function validateSession(req) {
  // Extract token from Authorization header or cookie
  const accessToken = req.headers.authorization?.replace('Bearer ', '') || req.cookies.accessToken;
  
  if (!accessToken) {
    throw new Error('No access token provided');
  }
  
  // Verify JWT signature and expiration
  const payload = verifyJWT(accessToken);
  if (!payload) {
    throw new Error('Invalid or expired access token');
  }
  
  // Check if user is revoked
  const revoked = await redis.get(`user:${payload.sub}:revoked`);
  if (revoked) {
    throw new Error('Session has been revoked');
  }
  
  // Load user data (with caching)
  let user = await redis.get(`user:${payload.sub}:data`);
  if (!user) {
    user = await User.findById(payload.sub);
    await redis.setex(`user:${payload.sub}:data`, 300, JSON.stringify(user));
  } else {
    user = JSON.parse(user);
  }
  
  return { user, payload };
}
```

**Session Timeout:**
```javascript
const sessionConfig = {
  idleTimeout: 30 * 60 * 1000, // 30 minutes
  absoluteTimeout: 8 * 60 * 60 * 1000 // 8 hours
};

async function checkSessionTimeout(sessionId) {
  const session = await Session.findById(sessionId);
  
  if (!session) {
    return { valid: false, reason: 'Session not found' };
  }
  
  const now = new Date();
  
  // Check absolute timeout
  if (now - session.createdAt > sessionConfig.absoluteTimeout) {
    await deleteSession(sessionId);
    return { valid: false, reason: 'Absolute timeout exceeded' };
  }
  
  // Check idle timeout
  if (now - session.lastActivity > sessionConfig.idleTimeout) {
    await deleteSession(sessionId);
    return { valid: false, reason: 'Idle timeout exceeded' };
  }
  
  // Update last activity
  await Session.update({ id: sessionId }, { lastActivity: now });
  await redis.expire(`session:${sessionId}`, 1800); // Extend TTL
  
  return { valid: true };
}
```

**Session Termination:**
```javascript
async function logout(sessionId) {
  // Delete from database
  await Session.delete({ id: sessionId });
  
  // Delete from Redis
  await redis.del(`session:${sessionId}`);
  
  // Audit log
  await AuditLog.create({
    sessionId,
    eventType: 'LOGOUT',
    timestamp: new Date()
  });
}

async function logoutAllDevices(userId) {
  // Delete all sessions
  await Session.delete({ userId });
  
  // Delete from Redis
  const keys = await redis.keys(`session:*`);
  for (const key of keys) {
    const data = await redis.get(key);
    if (data && JSON.parse(data).userId === userId) {
      await redis.del(key);
    }
  }
  
  // Add to revocation list
  await redis.setex(`user:${userId}:revoked`, 86400, Date.now());
}
```

### Session Security

**Cookie Configuration:**
```javascript
const cookieConfig = {
  httpOnly: true, // Prevent JavaScript access
  secure: true, // HTTPS only
  sameSite: 'strict', // CSRF protection
  maxAge: 86400000, // 24 hours
  domain: '.example.com', // Share across subdomains
  path: '/'
};

// Set cookies
res.cookie('accessToken', accessToken, cookieConfig);
res.cookie('refreshToken', refreshToken, {
  ...cookieConfig,
  maxAge: 604800000 // 7 days for refresh token
});
```

**CSRF Protection:**
```javascript
const csrf = require('csurf');

// CSRF middleware
const csrfProtection = csrf({
  cookie: {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
  }
});

// Apply to state-changing routes
app.post('/api/*', csrfProtection, (req, res, next) => {
  // CSRF token validated automatically
  next();
});

// Provide CSRF token to frontend
app.get('/api/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});
```

**Session Fixation Prevention:**
```javascript
async function regenerateSessionId(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      resolve();
    });
  });
}

// Regenerate after login
app.post('/auth/login', async (req, res) => {
  const user = await authenticateUser(req.body.email, req.body.password);
  
  // Regenerate session ID
  await regenerateSessionId(req);
  
  // Set new session data
  req.session.userId = user.id;
  req.session.roles = user.roles;
  
  res.json({ success: true });
});
```

**Concurrent Session Limiting:**
```javascript
const MAX_CONCURRENT_SESSIONS = 5;

async function enforceConcurrentSessionLimit(userId) {
  const sessions = await Session.find({ userId }).sort({ createdAt: -1 });
  
  if (sessions.length >= MAX_CONCURRENT_SESSIONS) {
    // Delete oldest sessions
    const sessionsToDelete = sessions.slice(MAX_CONCURRENT_SESSIONS - 1);
    for (const session of sessionsToDelete) {
      await deleteSession(session.id);
    }
  }
}

// Session management UI
app.get('/api/sessions', authenticate, async (req, res) => {
  const sessions = await Session.find({ userId: req.user.id });
  res.json({
    sessions: sessions.map(s => ({
      id: s.id,
      deviceFingerprint: s.deviceFingerprint,
      ipAddress: s.ipAddress,
      createdAt: s.createdAt,
      lastActivity: s.lastActivity,
      current: s.id === req.sessionId
    }))
  });
});

app.delete('/api/sessions/:id', authenticate, async (req, res) => {
  const session = await Session.findOne({ 
    id: req.params.id, 
    userId: req.user.id 
  });
  
  if (!session) {
    return res.status(404).json({ error: 'Session not found' });
  }
  
  await deleteSession(session.id);
  res.json({ success: true });
});
```

**Device Fingerprinting:**
```javascript
const crypto = require('crypto');

function generateDeviceFingerprint(req) {
  const components = [
    req.headers['user-agent'],
    req.headers['accept-language'],
    req.headers['accept-encoding'],
    req.ip
  ];
  
  const fingerprint = components.join('|');
  return crypto.createHash('sha256').update(fingerprint).digest('hex');
}

async function validateDeviceFingerprint(sessionId, req) {
  const session = await Session.findById(sessionId);
  const currentFingerprint = generateDeviceFingerprint(req);
  
  if (session.deviceFingerprint !== currentFingerprint) {
    // Fingerprint mismatch - potential session hijacking
    await AuditLog.create({
      sessionId,
      eventType: 'FINGERPRINT_MISMATCH',
      oldFingerprint: session.deviceFingerprint,
      newFingerprint: currentFingerprint,
      ipAddress: req.ip
    });
    
    // Optional: Invalidate session
    // await deleteSession(sessionId);
    // throw new Error('Device fingerprint mismatch');
    
    // Or: Require re-authentication
    return { valid: false, requireReauth: true };
  }
  
  return { valid: true };
}
```

---

## 5. Token-Based Authentication Architecture

### Access Token Design

**Token Configuration:**
```javascript
const accessTokenConfig = {
  algorithm: 'RS256', // RSA-SHA256 (asymmetric)
  expiresIn: '30m', // 30 minutes
  issuer: 'https://app.example.com',
  audience: 'https://app.example.com'
};
```

**Token Generation:**
```javascript
const jwt = require('jsonwebtoken');
const fs = require('fs');

const privateKey = fs.readFileSync('./keys/jwt-private.pem', 'utf8');

function generateAccessToken(user) {
  const payload = {
    sub: user.id,
    email: user.email,
    roles: user.roles,
    permissions: user.permissions,
    iat: Math.floor(Date.now() / 1000),
    exp: Math.floor(Date.now() / 1000) + (30 * 60)
  };
  
  return jwt.sign(payload, privateKey, {
    algorithm: 'RS256',
    issuer: accessTokenConfig.issuer,
    audience: accessTokenConfig.audience
  });
}
```

**Token Validation:**
```javascript
const publicKey = fs.readFileSync('./keys/jwt-public.pem', 'utf8');

async function validateAccessToken(token) {
  try {
    // Verify signature and claims
    const payload = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: accessTokenConfig.issuer,
      audience: accessTokenConfig.audience
    });
    
    // Check expiration
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return { valid: false, error: 'Token expired' };
    }
    
    // Check revocation (blacklist)
    const revoked = await redis.get(`token:blacklist:${token}`);
    if (revoked) {
      return { valid: false, error: 'Token revoked' };
    }
    
    // Check user still exists and is active
    const user = await User.findById(payload.sub);
    if (!user || !user.active) {
      return { valid: false, error: 'User inactive' };
    }
    
    return { valid: true, payload, user };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}
```

**Token Revocation (Blacklist):**
```javascript
async function revokeAccessToken(token) {
  const payload = jwt.decode(token);
  if (!payload) return;
  
  const ttl = payload.exp - Math.floor(Date.now() / 1000);
  if (ttl > 0) {
    await redis.setex(`token:blacklist:${token}`, ttl, '1');
  }
}
```

### Refresh Token Design

**Token Configuration:**
```javascript
const refreshTokenConfig = {
  lifetime: 7 * 24 * 60 * 60 * 1000, // 7 days
  rotation: true, // Rotate on every use
  reuseDetection: true // Detect token reuse (security breach)
};
```

**Token Generation:**
```javascript
const crypto = require('crypto');

async function generateRefreshToken(user, deviceFingerprint) {
  const token = crypto.randomBytes(32).toString('hex');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  
  const refreshToken = await RefreshToken.create({
    userId: user.id,
    tokenHash,
    deviceFingerprint,
    expiresAt: new Date(Date.now() + refreshTokenConfig.lifetime),
    revoked: false,
    used: false
  });
  
  return { token, id: refreshToken.id };
}
```

**Token Storage:**
```javascript
// Database table
CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  device_fingerprint VARCHAR(64),
  parent_token_id UUID REFERENCES refresh_tokens(id), -- For rotation chain
  used BOOLEAN DEFAULT FALSE,
  revoked BOOLEAN DEFAULT FALSE,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT NOW(),
  last_used_at TIMESTAMP
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token_hash ON refresh_tokens(token_hash);
CREATE INDEX idx_refresh_tokens_expires_at ON refresh_tokens(expires_at);
```

**Token Rotation:**
```javascript
async function refreshAccessToken(refreshTokenString, deviceFingerprint) {
  const tokenHash = crypto.createHash('sha256').update(refreshTokenString).digest('hex');
  
  // Find refresh token
  const refreshToken = await RefreshToken.findOne({
    tokenHash,
    revoked: false,
    expiresAt: { $gte: new Date() }
  });
  
  if (!refreshToken) {
    throw new Error('Invalid refresh token');
  }
  
  // Check if already used (token reuse detection)
  if (refreshToken.used && refreshTokenConfig.reuseDetection) {
    // Potential security breach - revoke entire token chain
    await revokeTokenChain(refreshToken.id);
    throw new Error('Refresh token reused - security breach detected');
  }
  
  // Validate device fingerprint
  if (refreshToken.deviceFingerprint !== deviceFingerprint) {
    throw new Error('Device fingerprint mismatch');
  }
  
  // Load user
  const user = await User.findById(refreshToken.userId);
  if (!user || !user.active) {
    throw new Error('User not found or inactive');
  }
  
  // Generate new access token
  const accessToken = generateAccessToken(user);
  
  // Generate new refresh token (rotation)
  const newRefreshToken = await generateRefreshToken(user, deviceFingerprint);
  
  // Mark old token as used and link to new token
  await RefreshToken.update({ id: refreshToken.id }, {
    used: true,
    lastUsedAt: new Date()
  });
  
  // Store parent-child relationship
  await RefreshToken.update({ id: newRefreshToken.id }, {
    parentTokenId: refreshToken.id
  });
  
  return {
    accessToken,
    refreshToken: newRefreshToken.token,
    expiresIn: 1800 // 30 minutes
  };
}
```

**Token Reuse Detection:**
```javascript
async function revokeTokenChain(tokenId) {
  // Find all tokens in the chain
  const tokens = [];
  let currentId = tokenId;
  
  // Traverse up to find root
  while (currentId) {
    const token = await RefreshToken.findById(currentId);
    if (!token) break;
    tokens.push(token);
    currentId = token.parentTokenId;
  }
  
  // Traverse down to find all children
  const findChildren = async (parentId) => {
    const children = await RefreshToken.find({ parentTokenId: parentId });
    for (const child of children) {
      tokens.push(child);
      await findChildren(child.id);
    }
  };
  await findChildren(tokenId);
  
  // Revoke all tokens in chain
  const tokenIds = tokens.map(t => t.id);
  await RefreshToken.updateMany({ id: { $in: tokenIds } }, { revoked: true });
  
  // Log security event
  await AuditLog.create({
    eventType: 'TOKEN_CHAIN_REVOKED',
    userId: tokens[0].userId,
    reason: 'Refresh token reuse detected',
    affectedTokens: tokenIds.length
  });
}
```

**Token Binding (Device Fingerprint):**
```javascript
function generateSecureDeviceFingerprint(req) {
  const components = [
    req.headers['user-agent'],
    req.headers['accept-language'],
    req.ip,
    req.headers['sec-ch-ua'], // Client hints
    req.headers['sec-ch-ua-mobile'],
    req.headers['sec-ch-ua-platform']
  ].filter(Boolean);
  
  return crypto.createHash('sha256').update(components.join('|')).digest('hex');
}
```

### API Key Authentication

**API Key Configuration:**
```javascript
const apiKeyConfig = {
  prefix: {
    live: 'sk_live_',
    test: 'sk_test_'
  },
  length: 32, // bytes
  hashAlgorithm: 'sha256'
};
```

**Key Generation:**
```javascript
function generateAPIKey(environment = 'live') {
  const randomBytes = crypto.randomBytes(apiKeyConfig.length);
  const key = randomBytes.toString('base64url');
  const prefix = apiKeyConfig.prefix[environment];
  return `${prefix}${key}`;
}

function hashAPIKey(apiKey) {
  return crypto.createHash(apiKeyConfig.hashAlgorithm).update(apiKey).digest('hex');
}
```

**API Key Storage:**
```sql
CREATE TABLE api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  key_hash VARCHAR(64) NOT NULL UNIQUE,
  key_prefix VARCHAR(20) NOT NULL,
  environment VARCHAR(10) NOT NULL CHECK (environment IN ('live', 'test')),
  scopes TEXT[] NOT NULL,
  rate_limit INTEGER DEFAULT 1000,
  expires_at TIMESTAMP,
  last_used_at TIMESTAMP,
  created_at TIMESTAMP DEFAULT NOW(),
  revoked BOOLEAN DEFAULT FALSE
);

CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
```

**API Key Validation:**
```javascript
async function validateAPIKey(apiKey) {
  // Extract prefix
  const prefix = apiKey.substring(0, 8);
  const environment = prefix.startsWith('sk_live_') ? 'live' : 'test';
  
  // Hash key
  const keyHash = hashAPIKey(apiKey);
  
  // Find in database
  const key = await APIKey.findOne({
    keyHash,
    revoked: false
  });
  
  if (!key) {
    return { valid: false, error: 'Invalid API key' };
  }
  
  // Check expiration
  if (key.expiresAt && key.expiresAt < new Date()) {
    return { valid: false, error: 'API key expired' };
  }
  
  // Update last used
  await APIKey.update({ id: key.id }, { lastUsedAt: new Date() });
  
  // Load user
  const user = await User.findById(key.userId);
  
  return {
    valid: true,
    key,
    user,
    environment
  };
}
```

**API Key Permissions:**
```javascript
const apiKeyScopes = {
  'read:users': 'Read user data',
  'write:users': 'Create and update users',
  'read:transactions': 'Read transaction data',
  'write:transactions': 'Create and update transactions',
  'read:reports': 'Generate and read reports',
  'admin': 'Full administrative access'
};

function validateAPIKeyScopes(key, requiredScopes) {
  return requiredScopes.every(scope => key.scopes.includes(scope));
}

// Middleware
function requireAPIKeyScope(...requiredScopes) {
  return async (req, res, next) => {
    if (!req.apiKey) {
      return res.status(401).json({ error: 'API key required' });
    }
    
    if (!validateAPIKeyScopes(req.apiKey, requiredScopes)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    next();
  };
}

// Usage
app.post('/api/transactions', 
  authenticateAPIKey,
  requireAPIKeyScope('write:transactions'),
  async (req, res) => {
    // Handler
  }
);
```

**API Key Rotation:**
```javascript
async function rotateAPIKey(keyId, userId) {
  // Verify ownership
  const oldKey = await APIKey.findOne({ id: keyId, userId });
  if (!oldKey) {
    throw new Error('API key not found');
  }
  
  // Generate new key
  const newAPIKey = generateAPIKey(oldKey.environment);
  const newKeyHash = hashAPIKey(newAPIKey);
  
  // Create new key with same permissions
  const newKey = await APIKey.create({
    userId,
    name: oldKey.name + ' (rotated)',
    keyHash: newKeyHash,
    keyPrefix: newAPIKey.substring(0, 8),
    environment: oldKey.environment,
    scopes: oldKey.scopes,
    rateLimit: oldKey.rateLimit,
    expiresAt: oldKey.expiresAt
  });
  
  // Mark old key as revoked (keep for audit)
  await APIKey.update({ id: keyId }, { revoked: true });
  
  // Audit log
  await AuditLog.create({
    eventType: 'API_KEY_ROTATED',
    userId,
    oldKeyId: keyId,
    newKeyId: newKey.id
  });
  
  return {
    apiKey: newAPIKey,
    keyId: newKey.id,
    message: 'API key rotated successfully. Update your application with the new key.'
  };
}
```

---

## 6. Login Security Features

### Rate Limiting

**Failed Login Rate Limiter:**
```javascript
const RateLimiterFlexible = require('rate-limiter-flexible');

// Per-account rate limiter (5 attempts per 15 minutes)
const accountLimiter = new RateLimiterFlexible.RateLimiterMemory({
  points: 5,
  duration: 15 * 60,
  blockDuration: 15 * 60
});

// Per-IP rate limiter (20 attempts per hour)
const ipLimiter = new RateLimiterFlexible.RateLimiterMemory({
  points: 20,
  duration: 60 * 60,
  blockDuration: 60 * 60
});

async function checkLoginRateLimit(email, ip) {
  try {
    // Check account-based limit
    await accountLimiter.consume(email);
    
    // Check IP-based limit
    await ipLimiter.consume(ip);
    
    return { allowed: true };
  } catch (error) {
    if (error instanceof Error) {
      throw error;
    }
    
    // Rate limit exceeded
    return {
      allowed: false,
      retryAfter: Math.ceil(error.msBeforeNext / 1000)
    };
  }
}
```

**Account Lockout:**
```javascript
const LOCKOUT_THRESHOLD = 5;
const LOCKOUT_DURATION = 30 * 60 * 1000; // 30 minutes

async function handleFailedLogin(userId) {
  const user = await User.findById(userId);
  
  // Increment failed attempts
  const failedAttempts = (user.failedLoginAttempts || 0) + 1;
  
  if (failedAttempts >= LOCKOUT_THRESHOLD) {
    // Lock account
    await User.update({ id: userId }, {
      failedLoginAttempts: failedAttempts,
      lockedUntil: new Date(Date.now() + LOCKOUT_DURATION),
      accountLocked: true
    });
    
    // Send notification email
    await sendAccountLockedEmail(user.email);
    
    // Audit log
    await AuditLog.create({
      userId,
      eventType: 'ACCOUNT_LOCKED',
      reason: 'Too many failed login attempts'
    });
    
    return { locked: true, lockedUntil: new Date(Date.now() + LOCKOUT_DURATION) };
  } else {
    await User.update({ id: userId }, { failedLoginAttempts: failedAttempts });
    return { locked: false, remainingAttempts: LOCKOUT_THRESHOLD - failedAttempts };
  }
}

async function checkAccountLockout(userId) {
  const user = await User.findById(userId);
  
  if (user.accountLocked && user.lockedUntil) {
    if (new Date() < user.lockedUntil) {
      return { locked: true, lockedUntil: user.lockedUntil };
    } else {
      // Unlock account
      await User.update({ id: userId }, {
        accountLocked: false,
        lockedUntil: null,
        failedLoginAttempts: 0
      });
    }
  }
  
  return { locked: false };
}

async function handleSuccessfulLogin(userId) {
  // Reset failed login attempts
  await User.update({ id: userId }, {
    failedLoginAttempts: 0,
    lastLoginAt: new Date()
  });
}
```

**Exponential Backoff:**
```javascript
async function calculateLoginDelay(failedAttempts) {
  // Exponential backoff: 2^(attempts-1) seconds
  if (failedAttempts <= 1) return 0;
  
  const delaySeconds = Math.pow(2, failedAttempts - 1);
  const maxDelay = 60; // Cap at 60 seconds
  
  return Math.min(delaySeconds, maxDelay) * 1000; // Convert to milliseconds
}

// Usage in login endpoint
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  
  const user = await User.findOne({ email });
  if (!user) {
    // Generic error (prevent user enumeration)
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  
  // Calculate delay based on previous failed attempts
  const delay = await calculateLoginDelay(user.failedLoginAttempts);
  if (delay > 0) {
    await new Promise(resolve => setTimeout(resolve, delay));
  }
  
  // ... rest of login logic
});
```

### CAPTCHA Integration

**reCAPTCHA v3 Configuration:**
```javascript
const RECAPTCHA_SECRET = process.env.RECAPTCHA_SECRET_KEY;
const RECAPTCHA_THRESHOLD = 0.5;

async function verifyRecaptcha(token, action) {
  const response = await axios.post('https://www.google.com/recaptcha/api/siteverify', null, {
    params: {
      secret: RECAPTCHA_SECRET,
      response: token
    }
  });
  
  const data = response.data;
  
  if (!data.success) {
    return { valid: false, error: 'CAPTCHA verification failed' };
  }
  
  if (data.action !== action) {
    return { valid: false, error: 'CAPTCHA action mismatch' };
  }
  
  if (data.score < RECAPTCHA_THRESHOLD) {
    return { valid: false, error: 'CAPTCHA score too low', score: data.score };
  }
  
  return { valid: true, score: data.score };
}
```

**Trigger CAPTCHA After Failed Attempts:**
```javascript
const CAPTCHA_TRIGGER_THRESHOLD = 3;

async function shouldRequireCaptcha(email, ip) {
  const user = await User.findOne({ email });
  
  if (user && user.failedLoginAttempts >= CAPTCHA_TRIGGER_THRESHOLD) {
    return true;
  }
  
  // Check IP-based failed attempts
  const ipAttempts = await redis.get(`failed_login:${ip}`);
  if (ipAttempts && parseInt(ipAttempts) >= CAPTCHA_TRIGGER_THRESHOLD) {
    return true;
  }
  
  return false;
}

// Login endpoint with CAPTCHA
app.post('/auth/login', async (req, res) => {
  const { email, password, recaptchaToken } = req.body;
  const ip = req.ip;
  
  // Check if CAPTCHA required
  const requireCaptcha = await shouldRequireCaptcha(email, ip);
  
  if (requireCaptcha) {
    if (!recaptchaToken) {
      return res.status(400).json({ 
        error: 'CAPTCHA required',
        requireCaptcha: true 
      });
    }
    
    const captchaResult = await verifyRecaptcha(recaptchaToken, 'login');
    if (!captchaResult.valid) {
      return res.status(400).json({ 
        error: 'CAPTCHA verification failed',
        requireCaptcha: true 
      });
    }
  }
  
  // ... rest of login logic
});
```

**hCaptcha Integration (Alternative):**
```javascript
const HCAPTCHA_SECRET = process.env.HCAPTCHA_SECRET_KEY;

async function verifyHcaptcha(token) {
  const response = await axios.post('https://hcaptcha.com/siteverify', 
    `response=${token}&secret=${HCAPTCHA_SECRET}`,
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
    }
  );
  
  return response.data.success;
}
```

**Accessibility - Audio CAPTCHA:**
```html
<!-- Frontend implementation -->
<div class="h-captcha" 
     data-sitekey="your-site-key"
     data-theme="light"
     data-size="normal"
     data-hl="en">
</div>

<script src="https://hcaptcha.com/1/api.js" async defer></script>
```

### Security Logging

**Event Types:**
```javascript
const AUTH_EVENTS = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILURE: 'LOGIN_FAILURE',
  MFA_SUCCESS: 'MFA_SUCCESS',
  MFA_FAILURE: 'MFA_FAILURE',
  PASSWORD_RESET_REQUESTED: 'PASSWORD_RESET_REQUESTED',
  PASSWORD_RESET_COMPLETED: 'PASSWORD_RESET_COMPLETED',
  PASSWORD_CHANGED: 'PASSWORD_CHANGED',
  ACCOUNT_LOCKED: 'ACCOUNT_LOCKED',
  ACCOUNT_UNLOCKED: 'ACCOUNT_UNLOCKED',
  SESSION_CREATED: 'SESSION_CREATED',
  SESSION_TERMINATED: 'SESSION_TERMINATED',
  TOKEN_REFRESHED: 'TOKEN_REFRESHED',
  EMAIL_VERIFIED: 'EMAIL_VERIFIED'
};
```

**Audit Log Schema:**
```sql
CREATE TABLE auth_audit_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  event_type VARCHAR(50) NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  device_fingerprint VARCHAR(64),
  result VARCHAR(20) NOT NULL CHECK (result IN ('success', 'failure', 'pending')),
  failure_reason TEXT,
  metadata JSONB,
  created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_auth_audit_log_user_id ON auth_audit_log(user_id);
CREATE INDEX idx_auth_audit_log_event_type ON auth_audit_log(event_type);
CREATE INDEX idx_auth_audit_log_created_at ON auth_audit_log(created_at);
CREATE INDEX idx_auth_audit_log_ip_address ON auth_audit_log(ip_address);
```

**Logging Function:**
```javascript
async function logAuthEvent(event)