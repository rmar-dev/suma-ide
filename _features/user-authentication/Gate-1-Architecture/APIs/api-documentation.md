---
layout: default
title: Api Documentation
parent: User Authentication
grand_parent: Features
nav_exclude: true
---

# API Documentation Architecture - SUMA Finance

**Project**: SUMA Finance  
**Feature**: User Registration & Authentication  
**Gate**: Gate 1 - API Documentation Architecture  
**Version**: 1.0  
**Date**: 2025-11-02

---

## 1. API Documentation Overview

### API Architecture Style
- **Primary Architecture**: RESTful API
- **Protocol**: HTTPS only (TLS 1.2+)
- **Data Format**: JSON (primary), form-urlencoded (authentication flows)
- **API Style**: Resource-oriented REST

### API Documentation Standards
- **Specification**: OpenAPI 3.0.3
- **Documentation Format**: Swagger/OpenAPI compliant
- **Schema Validation**: JSON Schema Draft 2020-12
- **Interactive Documentation**: Swagger UI + Redoc

### API Versioning Strategy
- **Version Scheme**: URI path versioning (`/api/v1/`)
- **Current Version**: v1
- **Version Format**: `/api/v{major}/`
- **Deprecation Policy**: 12-month notice period

### Base URLs and Environments

| Environment | Base URL | Purpose |
|------------|----------|---------|
| Production | `https://api.suma.finance/api/v1` | Live production API |
| Staging | `https://api-staging.suma.finance/api/v1` | Pre-production testing |
| Development | `https://api-dev.suma.finance/api/v1` | Development environment |
| Sandbox | `https://api-sandbox.suma.finance/api/v1` | Developer testing |

### Documentation Hosting
- **Swagger UI**: `https://docs.suma.finance/swagger-ui`
- **Redoc**: `https://docs.suma.finance/redoc`
- **API Portal**: `https://developers.suma.finance`
- **Postman Collection**: Available at developer portal
- **OpenAPI Spec**: `https://api.suma.finance/api/v1/openapi.json`

---

## 2. RESTful API Design Standards

### Resource Naming Conventions
- **Collections**: Plural nouns (`/users`, `/sessions`)
- **Single Resource**: Singular identifier (`/users/{userId}`)
- **Nested Resources**: Logical hierarchy (`/users/{userId}/sessions`)
- **No Verbs**: Actions implied by HTTP methods
- **Lowercase**: All lowercase with hyphens for readability (`/password-reset`)

**Examples**:
```
✅ GET /api/v1/users
✅ POST /api/v1/users
✅ GET /api/v1/users/{userId}
✅ POST /api/v1/auth/login
✅ POST /api/v1/auth/password-reset

❌ GET /api/v1/getUsers
❌ POST /api/v1/createUser
❌ GET /api/v1/user/{userId}
```

### HTTP Methods Usage

| Method | Purpose | Idempotent | Request Body | Response Body |
|--------|---------|------------|--------------|---------------|
| GET | Retrieve resource(s) | Yes | No | Yes |
| POST | Create new resource | No | Yes | Yes |
| PUT | Replace entire resource | Yes | Yes | Yes |
| PATCH | Partial update | No | Yes | Yes |
| DELETE | Remove resource | Yes | Optional | Optional |
| HEAD | Retrieve headers only | Yes | No | No |
| OPTIONS | Get allowed methods | Yes | No | Yes |

### Response Status Codes

#### 2xx Success Codes
- **200 OK**: Successful GET, PUT, PATCH, DELETE
- **201 Created**: Successful POST creating new resource
- **202 Accepted**: Request accepted for async processing
- **204 No Content**: Successful request with no response body

#### 4xx Client Error Codes
- **400 Bad Request**: Invalid request syntax or validation error
- **401 Unauthorized**: Missing or invalid authentication
- **403 Forbidden**: Authenticated but insufficient permissions
- **404 Not Found**: Resource does not exist
- **409 Conflict**: Request conflicts with current state (duplicate email)
- **422 Unprocessable Entity**: Valid syntax but semantic errors
- **429 Too Many Requests**: Rate limit exceeded

#### 5xx Server Error Codes
- **500 Internal Server Error**: Unexpected server error
- **502 Bad Gateway**: Invalid upstream response
- **503 Service Unavailable**: Temporary unavailability
- **504 Gateway Timeout**: Upstream timeout

### URL Structure Standards

**Path Parameters**: Resource identifiers
```
/api/v1/users/{userId}
/api/v1/users/{userId}/sessions/{sessionId}
```

**Query Parameters**: Filtering, sorting, pagination
```
/api/v1/users?role=admin&status=active&page=2&limit=20&sort=createdAt:desc
```

**Standard Query Parameters**:
- `page`: Page number (default: 1)
- `limit`: Items per page (default: 20, max: 100)
- `sort`: Sort field and direction (`field:asc` or `field:desc`)
- `fields`: Partial response fields (`?fields=id,email,name`)
- `filter`: Complex filtering (implementation-specific)

---

## 3. API Endpoint Documentation Format

### User Registration Endpoints

#### POST /api/v1/auth/register

**Description**: Register a new user account with email and password.

**Authentication**: None (public endpoint)

**Rate Limiting**: 5 requests per hour per IP address

**Request**:

**Headers**:
```
Content-Type: application/json
Accept: application/json
X-Request-ID: <uuid> (optional)
```

**Path Parameters**: None

**Query Parameters**: None

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+351912345678",
  "acceptedTerms": true
}
```

**Request Schema**:
```json
{
  "type": "object",
  "required": ["email", "password", "firstName", "lastName", "acceptedTerms"],
  "properties": {
    "email": {
      "type": "string",
      "format": "email",
      "maxLength": 255,
      "description": "User's email address (must be unique)"
    },
    "password": {
      "type": "string",
      "minLength": 8,
      "maxLength": 128,
      "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
      "description": "Password (min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char)"
    },
    "firstName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100,
      "description": "User's first name"
    },
    "lastName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100,
      "description": "User's last name"
    },
    "phoneNumber": {
      "type": "string",
      "pattern": "^\\+[1-9]\\d{1,14}$",
      "description": "Phone number in E.164 format (optional)"
    },
    "acceptedTerms": {
      "type": "boolean",
      "const": true,
      "description": "Must accept terms and conditions"
    }
  }
}
```

**Response**:

**Success Response (201 Created)**:
```json
{
  "success": true,
  "data": {
    "userId": "usr_2Nq8vYZ1wX3mP9kL",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+351912345678",
    "emailVerified": false,
    "createdAt": "2025-11-02T10:30:00Z",
    "status": "pending_verification"
  },
  "message": "Registration successful. Please check your email to verify your account."
}
```

**Error Response (400 Bad Request)**:
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed",
    "details": [
      {
        "field": "password",
        "message": "Password must contain at least one uppercase letter",
        "code": "INVALID_FORMAT"
      }
    ],
    "requestId": "req_7Yx3mP9kL2Nq8vZ"
  }
}
```

**Error Response (409 Conflict)**:
```json
{
  "success": false,
  "error": {
    "code": "EMAIL_ALREADY_EXISTS",
    "message": "An account with this email address already exists",
    "requestId": "req_7Yx3mP9kL2Nq8vZ"
  }
}
```

**Code Examples**:

**cURL**:
```bash
curl -X POST https://api.suma.finance/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+351912345678",
    "acceptedTerms": true
  }'
```

**JavaScript (fetch)**:
```javascript
const response = await fetch('https://api.suma.finance/api/v1/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass123!',
    firstName: 'John',
    lastName: 'Doe',
    phoneNumber: '+351912345678',
    acceptedTerms: true
  })
});

const data = await response.json();

if (response.ok) {
  console.log('Registration successful:', data.data.userId);
} else {
  console.error('Registration failed:', data.error.message);
}
```

**JavaScript (axios)**:
```javascript
import axios from 'axios';

try {
  const response = await axios.post('https://api.suma.finance/api/v1/auth/register', {
    email: 'user@example.com',
    password: 'SecurePass123!',
    firstName: 'John',
    lastName: 'Doe',
    phoneNumber: '+351912345678',
    acceptedTerms: true
  }, {
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json'
    }
  });

  console.log('User created:', response.data.data.userId);
} catch (error) {
  if (error.response) {
    console.error('Error:', error.response.data.error.message);
  }
}
```

**Python (requests)**:
```python
import requests

url = 'https://api.suma.finance/api/v1/auth/register'
headers = {
    'Content-Type': 'application/json',
    'Accept': 'application/json'
}
payload = {
    'email': 'user@example.com',
    'password': 'SecurePass123!',
    'firstName': 'John',
    'lastName': 'Doe',
    'phoneNumber': '+351912345678',
    'acceptedTerms': True
}

response = requests.post(url, json=payload, headers=headers)

if response.status_code == 201:
    data = response.json()
    print(f"User created: {data['data']['userId']}")
else:
    error = response.json()
    print(f"Error: {error['error']['message']}")
```

**Java (HttpClient)**:
```java
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;

HttpClient client = HttpClient.newHttpClient();

String json = """
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "phoneNumber": "+351912345678",
  "acceptedTerms": true
}
""";

HttpRequest request = HttpRequest.newBuilder()
    .uri(URI.create("https://api.suma.finance/api/v1/auth/register"))
    .header("Content-Type", "application/json")
    .header("Accept", "application/json")
    .POST(HttpRequest.BodyPublishers.ofString(json))
    .build();

HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

if (response.statusCode() == 201) {
    System.out.println("Registration successful: " + response.body());
} else {
    System.err.println("Registration failed: " + response.body());
}
```

---

#### POST /api/v1/auth/verify-email

**Description**: Verify user's email address using verification token sent via email.

**Authentication**: None (token-based verification)

**Rate Limiting**: 10 requests per hour per IP address

**Request**:

**Headers**:
```
Content-Type: application/json
Accept: application/json
```

**Request Body**:
```json
{
  "token": "evt_3Kx9mP2nQ8vY1wZ4lL5",
  "email": "user@example.com"
}
```

**Request Schema**:
```json
{
  "type": "object",
  "required": ["token", "email"],
  "properties": {
    "token": {
      "type": "string",
      "minLength": 20,
      "maxLength": 255,
      "description": "Email verification token from verification email"
    },
    "email": {
      "type": "string",
      "format": "email",
      "description": "Email address being verified"
    }
  }
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "userId": "usr_2Nq8vYZ1wX3mP9kL",
    "email": "user@example.com",
    "emailVerified": true,
    "verifiedAt": "2025-11-02T10:45:00Z"
  },
  "message": "Email verified successfully. You can now log in."
}
```

**Error Response (400 Bad Request)**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_TOKEN",
    "message": "Invalid or expired verification token",
    "requestId": "req_9Yx3mP9kL2Nq8vZ"
  }
}
```

**Code Examples**:

**cURL**:
```bash
curl -X POST https://api.suma.finance/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "evt_3Kx9mP2nQ8vY1wZ4lL5",
    "email": "user@example.com"
  }'
```

**JavaScript (fetch)**:
```javascript
const response = await fetch('https://api.suma.finance/api/v1/auth/verify-email', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    token: 'evt_3Kx9mP2nQ8vY1wZ4lL5',
    email: 'user@example.com'
  })
});

const data = await response.json();
console.log(data.message);
```

---

#### POST /api/v1/auth/login

**Description**: Authenticate user with email and password, receive access token and refresh token.

**Authentication**: None (credentials-based)

**Rate Limiting**: 5 requests per 15 minutes per IP address

**Request**:

**Headers**:
```
Content-Type: application/json
Accept: application/json
User-Agent: <client-identifier>
X-Device-ID: <unique-device-id> (optional)
```

**Request Body**:
```json
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "rememberMe": true
}
```

**Request Schema**:
```json
{
  "type": "object",
  "required": ["email", "password"],
  "properties": {
    "email": {
      "type": "string",
      "format": "email",
      "description": "User's email address"
    },
    "password": {
      "type": "string",
      "description": "User's password"
    },
    "rememberMe": {
      "type": "boolean",
      "default": false,
      "description": "Extend session duration if true"
    }
  }
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "rt_8Kx9mP2nQ3vY1wZ4lL5Nx7",
    "tokenType": "Bearer",
    "expiresIn": 3600,
    "user": {
      "userId": "usr_2Nq8vYZ1wX3mP9kL",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "emailVerified": true,
      "phoneNumber": "+351912345678",
      "role": "user",
      "createdAt": "2025-11-02T10:30:00Z"
    }
  },
  "message": "Login successful"
}
```

**Error Response (401 Unauthorized)**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "requestId": "req_5Yx3mP9kL2Nq8vZ"
  }
}
```

**Error Response (403 Forbidden)**:
```json
{
  "success": false,
  "error": {
    "code": "EMAIL_NOT_VERIFIED",
    "message": "Please verify your email address before logging in",
    "requestId": "req_6Yx3mP9kL2Nq8vZ"
  }
}
```

**Code Examples**:

**cURL**:
```bash
curl -X POST https://api.suma.finance/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "rememberMe": true
  }'
```

**JavaScript (fetch)**:
```javascript
const response = await fetch('https://api.suma.finance/api/v1/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'SecurePass123!',
    rememberMe: true
  })
});

const data = await response.json();

if (response.ok) {
  // Store tokens securely
  localStorage.setItem('accessToken', data.data.accessToken);
  localStorage.setItem('refreshToken', data.data.refreshToken);
  console.log('Logged in as:', data.data.user.email);
} else {
  console.error('Login failed:', data.error.message);
}
```

**Python (requests)**:
```python
import requests

response = requests.post(
    'https://api.suma.finance/api/v1/auth/login',
    json={
        'email': 'user@example.com',
        'password': 'SecurePass123!',
        'rememberMe': True
    }
)

if response.status_code == 200:
    data = response.json()
    access_token = data['data']['accessToken']
    print(f"Logged in: {data['data']['user']['email']}")
else:
    error = response.json()
    print(f"Error: {error['error']['message']}")
```

---

#### POST /api/v1/auth/refresh

**Description**: Obtain a new access token using a valid refresh token.

**Authentication**: Refresh token required

**Rate Limiting**: 20 requests per hour per user

**Request**:

**Headers**:
```
Content-Type: application/json
Accept: application/json
```

**Request Body**:
```json
{
  "refreshToken": "rt_8Kx9mP2nQ3vY1wZ4lL5Nx7"
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "rt_9Kx9mP2nQ3vY1wZ4lL5Nx8",
    "tokenType": "Bearer",
    "expiresIn": 3600
  }
}
```

**Code Example (JavaScript)**:
```javascript
async function refreshAccessToken(refreshToken) {
  const response = await fetch('https://api.suma.finance/api/v1/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken })
  });

  if (response.ok) {
    const data = await response.json();
    localStorage.setItem('accessToken', data.data.accessToken);
    localStorage.setItem('refreshToken', data.data.refreshToken);
    return data.data.accessToken;
  } else {
    // Refresh failed, redirect to login
    window.location.href = '/login';
  }
}
```

---

#### POST /api/v1/auth/logout

**Description**: Invalidate current access token and refresh token.

**Authentication**: Bearer token required

**Rate Limiting**: 10 requests per hour per user

**Request**:

**Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
```

**Request Body**:
```json
{
  "refreshToken": "rt_8Kx9mP2nQ3vY1wZ4lL5Nx7"
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

**Code Example (JavaScript)**:
```javascript
async function logout() {
  const accessToken = localStorage.getItem('accessToken');
  const refreshToken = localStorage.getItem('refreshToken');

  await fetch('https://api.suma.finance/api/v1/auth/logout', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ refreshToken })
  });

  localStorage.removeItem('accessToken');
  localStorage.removeItem('refreshToken');
  window.location.href = '/login';
}
```

---

#### POST /api/v1/auth/password-reset/request

**Description**: Request password reset email with reset token.

**Authentication**: None (public endpoint)

**Rate Limiting**: 3 requests per hour per IP address

**Request**:

**Request Body**:
```json
{
  "email": "user@example.com"
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "message": "If an account with that email exists, a password reset link has been sent."
}
```

**Note**: Response is identical for existing and non-existing emails to prevent email enumeration.

**Code Example (JavaScript)**:
```javascript
async function requestPasswordReset(email) {
  const response = await fetch('https://api.suma.finance/api/v1/auth/password-reset/request', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email })
  });

  const data = await response.json();
  alert(data.message);
}
```

---

#### POST /api/v1/auth/password-reset/confirm

**Description**: Reset password using reset token.

**Authentication**: None (token-based)

**Rate Limiting**: 5 requests per hour per IP address

**Request**:

**Request Body**:
```json
{
  "token": "prt_3Kx9mP2nQ8vY1wZ4lL5",
  "email": "user@example.com",
  "newPassword": "NewSecurePass456!"
}
```

**Request Schema**:
```json
{
  "type": "object",
  "required": ["token", "email", "newPassword"],
  "properties": {
    "token": {
      "type": "string",
      "description": "Password reset token from email"
    },
    "email": {
      "type": "string",
      "format": "email"
    },
    "newPassword": {
      "type": "string",
      "minLength": 8,
      "maxLength": 128,
      "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$"
    }
  }
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "message": "Password reset successful. You can now log in with your new password."
}
```

---

#### GET /api/v1/users/me

**Description**: Get current authenticated user's profile.

**Authentication**: Bearer token required

**Rate Limiting**: 60 requests per minute per user

**Request**:

**Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "userId": "usr_2Nq8vYZ1wX3mP9kL",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "phoneNumber": "+351912345678",
    "emailVerified": true,
    "phoneVerified": false,
    "role": "user",
    "status": "active",
    "createdAt": "2025-11-02T10:30:00Z",
    "updatedAt": "2025-11-02T10:45:00Z",
    "lastLoginAt": "2025-11-02T14:20:00Z"
  }
}
```

**Code Example (JavaScript)**:
```javascript
async function getCurrentUser() {
  const accessToken = localStorage.getItem('accessToken');

  const response = await fetch('https://api.suma.finance/api/v1/users/me', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Accept': 'application/json'
    }
  });

  if (response.ok) {
    const data = await response.json();
    return data.data;
  } else if (response.status === 401) {
    // Token expired, try refresh
    await refreshAccessToken();
    return getCurrentUser(); // Retry
  }
}
```

---

#### PATCH /api/v1/users/me

**Description**: Update current authenticated user's profile.

**Authentication**: Bearer token required

**Rate Limiting**: 10 requests per hour per user

**Request**:

**Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Content-Type: application/json
```

**Request Body**:
```json
{
  "firstName": "Jane",
  "lastName": "Smith",
  "phoneNumber": "+351987654321"
}
```

**Request Schema**:
```json
{
  "type": "object",
  "properties": {
    "firstName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "lastName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "phoneNumber": {
      "type": "string",
      "pattern": "^\\+[1-9]\\d{1,14}$"
    }
  }
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "data": {
    "userId": "usr_2Nq8vYZ1wX3mP9kL",
    "email": "user@example.com",
    "firstName": "Jane",
    "lastName": "Smith",
    "phoneNumber": "+351987654321",
    "updatedAt": "2025-11-02T15:00:00Z"
  },
  "message": "Profile updated successfully"
}
```

**Code Example (JavaScript)**:
```javascript
async function updateProfile(updates) {
  const accessToken = localStorage.getItem('accessToken');

  const response = await fetch('https://api.suma.finance/api/v1/users/me', {
    method: 'PATCH',
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(updates)
  });

  return await response.json();
}
```

---

#### PUT /api/v1/users/me/password

**Description**: Change password for authenticated user (requires current password).

**Authentication**: Bearer token required

**Rate Limiting**: 5 requests per hour per user

**Request**:

**Request Body**:
```json
{
  "currentPassword": "SecurePass123!",
  "newPassword": "NewSecurePass456!"
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "message": "Password changed successfully"
}
```

**Error Response (401 Unauthorized)**:
```json
{
  "success": false,
  "error": {
    "code": "INVALID_CURRENT_PASSWORD",
    "message": "Current password is incorrect"
  }
}
```

---

#### DELETE /api/v1/users/me

**Description**: Delete current authenticated user's account (soft delete).

**Authentication**: Bearer token required

**Rate Limiting**: 1 request per day per user

**Request**:

**Headers**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Request Body**:
```json
{
  "password": "SecurePass123!",
  "confirmation": "DELETE_MY_ACCOUNT"
}
```

**Response**:

**Success Response (200 OK)**:
```json
{
  "success": true,
  "message": "Account deletion initiated. Your account will be permanently deleted in 30 days."
}
```

---

## 4. Data Models and Schemas

### Request DTOs

#### RegisterUserRequest
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["email", "password", "firstName", "lastName", "acceptedTerms"],
  "properties": {
    "email": {
      "type": "string",
      "format": "email",
      "maxLength": 255,
      "description": "User's email address (must be unique)",
      "examples": ["user@example.com"]
    },
    "password": {
      "type": "string",
      "minLength": 8,
      "maxLength": 128,
      "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
      "description": "Password (min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char)",
      "examples": ["SecurePass123!"]
    },
    "firstName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100,
      "description": "User's first name",
      "examples": ["John"]
    },
    "lastName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100,
      "description": "User's last name",
      "examples": ["Doe"]
    },
    "phoneNumber": {
      "type": "string",
      "pattern": "^\\+[1-9]\\d{1,14}$",
      "description": "Phone number in E.164 format",
      "examples": ["+351912345678"]
    },
    "acceptedTerms": {
      "type": "boolean",
      "const": true,
      "description": "Must be true to indicate acceptance of terms and conditions"
    }
  },
  "additionalProperties": false
}
```

#### LoginRequest
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["email", "password"],
  "properties": {
    "email": {
      "type": "string",
      "format": "email",
      "description": "User's email address"
    },
    "password": {
      "type": "string",
      "description": "User's password"
    },
    "rememberMe": {
      "type": "boolean",
      "default": false,
      "description": "Extend session duration if true"
    }
  },
  "additionalProperties": false
}
```

#### VerifyEmailRequest
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["token", "email"],
  "properties": {
    "token": {
      "type": "string",
      "minLength": 20,
      "maxLength": 255,
      "description": "Email verification token"
    },
    "email": {
      "type": "string",
      "format": "email",
      "description": "Email address being verified"
    }
  },
  "additionalProperties": false
}
```

#### UpdateProfileRequest
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {
    "firstName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "lastName": {
      "type": "string",
      "minLength": 1,
      "maxLength": 100
    },
    "phoneNumber": {
      "type": "string",
      "pattern": "^\\+[1-9]\\d{1,14}$"
    }
  },
  "additionalProperties": false,
  "minProperties": 1
}
```

### Response Models

#### UserResponse
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["userId", "email", "firstName", "lastName", "emailVerified", "role", "status", "createdAt"],
  "properties": {
    "userId": {
      "type": "string",
      "pattern": "^usr_[a-zA-Z0-9]{16}$",
      "description": "Unique user identifier",
      "examples": ["usr_2Nq8vYZ1wX3mP9kL"]
    },
    "email": {
      "type": "string",
      "format": "email"
    },
    "firstName": {
      "type": "string"
    },
    "lastName": {
      "type": "string"
    },
    "phoneNumber": {
      "type": "string",
      "pattern": "^\\+[1-9]\\d{1,14}$"
    },
    "emailVerified": {
      "type": "boolean"
    },
    "phoneVerified": {
      "type": "boolean"
    },
    "role": {
      "type": "string",
      "enum": ["user", "admin", "super_admin"]
    },
    "status": {
      "type": "string",
      "enum": ["pending_verification", "active", "suspended", "deleted"]
    },
    "createdAt": {
      "type": "string",
      "format": "date-time"
    },
    "updatedAt": {
      "type": "string",
      "format": "date-time"
    },
    "lastLoginAt": {
      "type": "string",
      "format": "date-time"
    }
  }
}
```

#### AuthenticationResponse
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["accessToken", "refreshToken", "tokenType", "expiresIn", "user"],
  "properties": {
    "accessToken": {
      "type": "string",
      "description": "JWT access token",
      "examples": ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."]
    },
    "refreshToken": {
      "type": "string",
      "pattern": "^rt_[a-zA-Z0-9]{20}$",
      "description": "Refresh token for obtaining new access tokens",
      "examples": ["rt_8Kx9mP2nQ3vY1wZ4lL5Nx7"]
    },
    "tokenType": {
      "type": "string",
      "const": "Bearer"
    },
    "expiresIn": {
      "type": "integer",
      "description": "Access token expiration time in seconds",
      "examples": [3600]
    },
    "user": {
      "$ref": "#/definitions/UserResponse"
    }
  }
}
```

### Common Models

#### SuccessResponse
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["success", "data"],
  "properties": {
    "success": {
      "type": "boolean",
      "const": true
    },
    "data": {
      "type": "object",
      "description": "Response payload (type varies by endpoint)"
    },
    "message": {
      "type": "string",
      "description": "Optional human-readable success message"
    }
  }
}
```

#### ErrorResponse
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["success", "error"],
  "properties": {
    "success": {
      "type": "boolean",
      "const": false
    },
    "error": {
      "type": "object",
      "required": ["code", "message"],
      "properties": {
        "code": {
          "type": "string",
          "description": "Machine-readable error code",
          "examples": ["VALIDATION_ERROR", "INVALID_CREDENTIALS"]
        },
        "message": {
          "type": "string",
          "description": "Human-readable error message",
          "examples": ["Invalid email or password"]
        },
        "details": {
          "type": "array",
          "description": "Detailed validation errors (if applicable)",
          "items": {
            "$ref": "#/definitions/ValidationError"
          }
        },
        "requestId": {
          "type": "string",
          "pattern": "^req_[a-zA-Z0-9]{16}$",
          "description": "Unique request identifier for tracing",
          "examples": ["req_7Yx3mP9kL2Nq8vZ"]
        }
      }
    }
  }
}
```

#### ValidationError
```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "required": ["field", "message", "code"],
  "properties": {
    "field": {
      "type": "string",
      "description": "Field name that failed validation",
      "examples": ["email", "password"]
    },
    "message": {
      "type": "string",
      "description": "Human-readable validation error message",
      "examples": ["Password must contain at least one uppercase letter"]
    },
    "code": {
      "type": "string",
      "description": "Machine-readable validation error code",
      "examples": ["INVALID_FORMAT", "REQUIRED_FIELD", "MIN_LENGTH"]
    },
    "rejectedValue": {
      "description": "The value that was rejected (optional, excluded for sensitive fields)"
    }
  }
}
```

### Enum Definitions

#### UserRole
```json
{
  "type": "string",
  "enum": ["user", "admin", "super_admin"],
  "description": "User role for authorization",
  "x-enum-descriptions": {
    "user": "Standard user with basic permissions",
    "admin": "Administrator with elevated permissions",
    "super_admin": "Super administrator with full system access"
  }
}
```

#### UserStatus
```json
{
  "type": "string",
  "enum": ["pending_verification", "active", "suspended", "deleted"],
  "description": "User account status",
  "x-enum-descriptions": {
    "pending_verification": "User registered but email not verified",
    "active": "Active user account",
    "suspended": "Account temporarily suspended",
    "deleted": "Account marked for deletion (soft delete)"
  }
}
```

---

## 5. Authentication Documentation

### Authentication Methods

**Primary Method**: JWT (JSON Web Tokens)

**Token Type**: Bearer tokens

**Token Storage**: 
- Access Token: Memory/Session storage (recommended)
- Refresh Token: HttpOnly secure cookie or secure storage

### How to Obtain Access Tokens

1. **User Registration Flow**:
   - POST `/api/v1/auth/register` with user details
   - Verify email via POST `/api/v1/auth/verify-email`
   - Login via POST `/api/v1/auth/login` to receive tokens

2. **Direct Login Flow**:
   - POST `/api/v1/auth/login` with email and password
   - Receive `accessToken` and `refreshToken` in response

3. **Token Refresh Flow**:
   - POST `/api/v1/auth/refresh` with `refreshToken`
   - Receive new `accessToken` and `refreshToken`

### Token Format and Structure

#### Access Token (JWT)

**Header**:
```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

**Payload**:
```json
{
  "sub": "usr_2Nq8vYZ1wX3mP9kL",
  "email": "user@example.com",
  "role": "user",
  "iat": 1730545200,
  "exp": 1730548800,
  "iss": "suma.finance",
  "aud": "suma-api"
}
```

**Claims**:
- `sub`: Subject (user ID)
- `email`: User's email
- `role`: User role for authorization
- `iat`: Issued at (Unix timestamp)
- `exp`: Expiration time (Unix timestamp)
- `iss`: Issuer (suma.finance)
- `aud`: Audience (suma-api)

#### Refresh Token

**Format**: Opaque token (cryptographically random string)

**Pattern**: `rt_[20 alphanumeric characters]`

**Example**: `rt_8Kx9mP2nQ3vY1wZ4lL5Nx7`

**Storage**: Database-backed, single-use tokens

### Token Placement

**Authorization Header (Recommended)**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**NOT Supported**:
- ❌ Query parameters (security risk)
- ❌ Cookies for API calls (use for web app only)

### Token Expiration and Refresh

| Token Type | Expiration (Default) | Expiration (Remember Me) | Renewable |
|-----------|---------------------|-------------------------|-----------|
| Access Token | 1 hour (3600s) | 1 hour (3600s) | Via refresh token |
| Refresh Token | 7 days | 30 days | On use (rotating tokens) |

**Token Refresh Strategy**:

1. **Proactive Refresh** (Recommended):
   ```javascript
   // Refresh token 5 minutes before expiration
   const expiresIn = 3600; // seconds
   const refreshBeforeExpiry = 300; // 5 minutes
   
   setTimeout(() => {
     refreshAccessToken();
   }, (expiresIn - refreshBeforeExpiry) * 1000);
   ```

2. **Reactive Refresh**:
   ```javascript
   // Refresh on 401 Unauthorized response
   if (response.status === 401) {
     const newToken = await refreshAccessToken();
     // Retry original request with new token
     return retryWithNewToken(newToken);
   }
   ```

### Example Authenticated Requests

**JavaScript (fetch)**:
```javascript
const accessToken = localStorage.getItem('accessToken');

const response = await fetch('https://api.suma.finance/api/v1/users/me', {
  method: 'GET',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Accept': 'application/json'
  }
});

if (response.status === 401) {
  // Token expired, refresh and retry
  const newToken = await refreshAccessToken();
  // Retry request...
}
```

**cURL**:
```bash
curl -X GET https://api.suma.finance/api/v1/users/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
  -H "Accept: application/json"
```

**Python (requests)**:
```python
import requests

access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

headers = {
    'Authorization': f'Bearer {access_token}',
    'Accept': 'application/json'
}

response = requests.get(
    'https://api.suma.finance/api/v1/users/me',
    headers=headers
)

if response.status_code == 401:
    # Refresh token and retry
    new_token = refresh_access_token()
    headers['Authorization'] = f'Bearer {new_token}'
    response = requests.get('https://api.suma.finance/api/v1/users/me', headers=headers)
```

### Authorization Header Format

**Standard Format**:
```
Authorization: Bearer <access_token>
```

**Example**:
```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c3JfMk5xOHZZWjF3WDNtUDlrTCIsImVtYWlsIjoidXNlckBleGFtcGxlLmNvbSIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzMwNTQ1MjAwLCJleHAiOjE3MzA1NDg4MDB9.signature
```

**Validation**:
- Token must be prefixed with `Bearer `
- Token format must be valid JWT (3 base64-encoded parts separated by dots)
- Token signature must be valid
- Token must not be expired
- Token must not be revoked/blacklisted

---

## 6. Error Handling Documentation

### Standard Error Response Format

All error responses follow a consistent structure:

```json
{
  "success": false,
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": [
      {
        "field": "fieldName",
        "message": "Field-specific error message",
        "code": "FIELD_ERROR_CODE"
      }
    ],
    "requestId": "req_7Yx3mP9kL2Nq8vZ"
  }
}
```

### Error Response Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `success` | boolean | Yes | Always `false` for errors |
| `error.code` | string | Yes | Machine-readable error code |
| `error.message` | string | Yes | Human-readable error message |
| `error.details` | array | No | Detailed validation errors (for 400/422 responses) |
| `error.requestId` | string | Yes | Unique request ID for tracing and support |

### Error Codes Catalog

#### Authentication Errors (401)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid email or password | Login credentials are incorrect |
| `TOKEN_EXPIRED` | 401 | Access token has expired | JWT token is expired, refresh required |
| `TOKEN_INVALID` | 401 | Invalid access token | JWT token is malformed or has invalid signature |
| `TOKEN_REVOKED` | 401 | Access token has been revoked | Token was invalidated (e.g., after logout) |
| `MISSING_AUTH_HEADER` | 401 | Authorization header is required | No Authorization header provided |
| `INVALID_AUTH_HEADER` | 401 | Invalid Authorization header format | Authorization header is malformed |

#### Authorization Errors (403)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `EMAIL_NOT_VERIFIED` | 403 | Please verify your email address before logging in | User must verify email first |
| `ACCOUNT_SUSPENDED` | 403 | Your account has been suspended | Account is suspended |
| `INSUFFICIENT_PERMISSIONS` | 403 | You do not have permission to perform this action | User lacks required permissions |

#### Validation Errors (400, 422)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed | One or more fields failed validation |
| `INVALID_EMAIL_FORMAT` | 400 | Invalid email address format | Email does not match email format |
| `INVALID_PASSWORD_FORMAT` | 400 | Password does not meet requirements | Password fails complexity requirements |
| `REQUIRED_FIELD` | 400 | Field is required | Required field is missing |
| `INVALID_PHONE_FORMAT` | 400 | Invalid phone number format | Phone number is not in E.164 format |
| `TERMS_NOT_ACCEPTED` | 400 | You must accept the terms and conditions | acceptedTerms is not true |

#### Conflict Errors (409)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `EMAIL_ALREADY_EXISTS` | 409 | An account with this email address already exists | Email is already registered |
| `DUPLICATE_RESOURCE` | 409 | Resource already exists | Attempting to create duplicate resource |

#### Not Found Errors (404)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `USER_NOT_FOUND` | 404 | User not found | User ID does not exist |
| `RESOURCE_NOT_FOUND` | 404 | Requested resource not found | Generic resource not found |
| `ENDPOINT_NOT_FOUND` | 404 | Endpoint not found | API endpoint does not exist |

#### Rate Limit Errors (429)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `RATE_LIMIT_EXCEEDED` | 429 | Rate limit exceeded. Please try again later. | Too many requests from this IP/user |

#### Server Errors (500)

| Error Code | HTTP Status | Message | Description |
|-----------|-------------|---------|-------------|
| `INTERNAL_SERVER_ERROR` | 500 | An unexpected error occurred. Please try again later. | Generic server error |
| `DATABASE_ERROR` | 500 | Database operation failed | Database connection or query error |
| `EXTERNAL_SERVICE_ERROR` | 500 | External service is unavailable | Third-party service error |

### Error Code to HTTP Status Mapping

```json
{
  "INVALID_CREDENTIALS": 401,
  "TOKEN_EXPIRED": 401,
  "TOKEN_INVALID": 401,
  "EMAIL_NOT_VERIFIED": 403,
  "ACCOUNT_SUSPENDED": 403,
  "VALIDATION_ERROR": 400,
  "EMAIL_ALREADY_EXISTS": 409,
  "USER_NOT_FOUND": 404,
  "RATE_LIMIT_EXCEEDED": 429,
  "INTERNAL_SERVER_ERROR": 500
}
```

### Error Handling Best Practices

#### 1. Retry Strategies

**Idempotent Requests (GET, PUT, DELETE)**:
```javascript
async function fetchWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      
      if (response.ok) {
        return response;
      }
      
      // Retry on 5xx errors
      if (response.status >= 500 && i < maxRetries - 1) {
        await sleep(Math.pow(2, i) * 1000); // Exponential backoff
        continue;
      }
      
      return response;
    } catch (error) {
      if (i === maxRetries - 1) throw error;
      await sleep(Math.pow(2, i) * 1000);
    }
  }
}
```

**Non-Idempotent Requests (POST)**:
- Use idempotency keys (see below)
- Only retry on network errors, NOT on HTTP errors
- Never auto-retry failed POST requests without idempotency keys

#### 2. Idempotency Keys

For critical POST requests (e.g., financial transactions):

```javascript
// Generate idempotency key
const idempotencyKey = `${userId}_${Date.now()}_${Math.random()}`;

const response = await fetch('https://api.suma.finance/api/v1/transactions', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': idempotencyKey
  },
  body: JSON.stringify({
    amount: 100.00,
    currency: 'EUR'
  })
});
```

**Server Behavior**:
- First request with key: Processes normally
- Duplicate request with same key within 24 hours: Returns cached response (200 OK)
- Duplicate request with same key (different payload): Returns 409 Conflict

#### 3. Handling Rate Limit Errors

**Response Headers**:
```
HTTP/1.1 429 Too Many Requests
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1730548800
Retry-After: 60
```

**Client Handling**:
```javascript
async function handleRateLimitedRequest(url, options) {
  const response = await fetch(url, options);
  
  if (response.status === 429) {
    const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
    console.log(`Rate limited. Retrying after ${retryAfter} seconds`);
    
    await sleep(retryAfter * 1000);
    return fetch(url, options); // Retry once
  }
  
  return response;
}
```

#### 4. Error Display Examples

**User-Friendly Error Messages**:
```javascript
function getErrorMessage(errorCode) {
  const messages = {
    'INVALID_CREDENTIALS': 'Invalid email or password. Please try again.',
    'EMAIL_ALREADY_EXISTS': 'An account with this email already exists. Try logging in instead.',
    'EMAIL_NOT_VERIFIED': 'Please verify your email address before logging in. Check your inbox.',
    'TOKEN_EXPIRED': 'Your session has expired. Please log in again.',
    'RATE_LIMIT_EXCEEDED': 'Too many attempts. Please wait a few minutes and try again.',
    'INTERNAL_SERVER_ERROR': 'Something went wrong on our end. Please try again later.',
    'VALIDATION_ERROR': 'Please check your input and try again.'
  };
  
  return messages[errorCode] || 'An unexpected error occurred. Please try again.';
}

// Usage
try {
  const response = await fetch('/api/v1/auth/login', {...});
  const data = await response.json();
  
  if (!response.ok) {
    const message = getErrorMessage(data.error.code);
    showErrorToast(message);
  }
} catch (error) {
  showErrorToast('Network error. Please check your connection.');
}
```

#### 5. Validation Error Display

```javascript
function displayValidationErrors(errorDetails) {
  errorDetails.forEach(error => {
    const fieldElement = document.getElementById(error.field);
    const errorElement = document.getElementById(`${error.field}-error`);
    
    if (fieldElement && errorElement) {
      fieldElement.classList.add('error');
      errorElement.textContent = error.message;
      errorElement.style.display = 'block';
    }
  });
}

// Usage
const response = await fetch('/api/v1/auth/register', {...});
const data = await response.json();

if (response.status === 400 && data.error.code === 'VALIDATION_ERROR') {
  displayValidationErrors(data.error.details);
}
```

---

## 7. Pagination, Filtering, and Sorting

### Pagination Strategies

#### Offset-Based Pagination (Default)

**Query Parameters**:
- `page`: Page number (1-indexed, default: 1)
- `limit`: Items per page (default: 20, max: 100)

**Request Example**:
```
GET /api/v1/users?page=2&limit=20
```

**Response Format**:
```json
{
  "success": true,
  "data": [
    {
      "userId": "usr_2Nq8vYZ1wX3mP9kL",
      "email": "user1@example.com",
      "firstName": "John",
      "lastName": "Doe"
    },
    {
      "userId": "usr_3Mq9wZA2xY4nQ0lM",
      "email": "user2@example.com",
      "firstName": "Jane",
      "lastName": "Smith"
    }
  ],
  "pagination": {
    "page": 2,
    "limit": 20,
    "totalItems": 157,
    "totalPages": 8,
    "hasNextPage": true,
    "hasPreviousPage": true
  }
}
```

**Pagination Metadata**:
```json
{
  "page": 2,
  "limit": 20,
  "totalItems": 157,
  "totalPages": 8,
  "hasNextPage": true,
  "hasPreviousPage": true
}
```

**JavaScript Example**:
```javascript
async function fetchUsers(page = 1, limit = 20) {
  const response = await fetch(
    `https://api.suma.finance/api/v1/users?page=${page}&limit=${limit}`,
    {
      headers: {
        'Authorization': `Bearer ${accessToken}`
      }
    }
  );
  
  const data = await response.json();
  
  return {
    users: data.data,
    pagination: data.pagination
  };
}

// Fetch next page
const { users, pagination } = await fetchUsers(2, 20);
console.log(`Showing page ${pagination.page} of ${pagination.totalPages}`);
```

#### Cursor-Based Pagination (For Large Datasets)

**Query Parameters**:
- `cursor`: Opaque cursor string (encoded pointer to next item)
- `limit`: Items per page (default: 20, max: 100)

**Request Example**:
```
GET /api/v1/transactions?cursor=eyJpZCI6MTAwLCJjcmVhdGVkX2F0IjoiMjAyNS0xMS0wMiJ9&limit=20
```

**Response Format**:
```json
{
  "success": true,
  "data": [...],
  "pagination": {
    "nextCursor": "eyJpZCI6MTIwLCJjcmVhdGVkX2F0IjoiMjAyNS0xMS0wMSJ9",
    "hasMore": true,
    "limit": 20
  }
}
```

**JavaScript Example**:
```javascript
async function fetchTransactions(cursor = null, limit = 20) {
  const params = new URLSearchParams({ limit });
  if (cursor) params.append('cursor', cursor);
  
  const response = await fetch(
    `https://api.suma.finance/api/v1/transactions?${params}`,
    {
      headers: { 'Authorization': `Bearer ${accessToken}` }
    }
  );
  
  return await response.json();
}

// Infinite scroll implementation
let cursor = null;
while (true) {
  const result = await fetchTransactions(cursor);
  displayTransactions(result.data);
  
  if (!result.pagination.hasMore) break;
  cursor = result.pagination.nextCursor;
}
```

### Filtering

**Query Parameter Syntax**:
```
GET /api/v1/users?status=active&role=admin&emailVerified=true
```

**Supported Filter Operators**:

| Operator | Syntax | Example | Description |
|----------|--------|---------|-------------|
| Equals | `field=value` | `status=active` | Exact match |
| Not equals | `field[ne]=value` | `role[ne]=user` | Not equal |
| Greater than | `field[gt]=value` | `createdAt[gt]=2025-01-01` | Greater than |
| Greater or equal | `field[gte]=value` | `amount[gte]=100` | Greater than or equal |
| Less than | `field[lt]=value` | `createdAt[lt]=2025-12-31` | Less than |
| Less or equal | `field[lte]=value` | `amount[lte]=1000` | Less than or equal |
| In | `field[in]=val1,val2` | `status[in]=active,pending` | Value in list |
| Contains | `field[contains]=value` | `email[contains]=@gmail` | String contains |

**Complex Filter Examples**:
```
GET /api/v1/users?status[in]=active,pending&createdAt[gte]=2025-01-01&emailVerified=true

GET /api/v1/transactions?amount[gte]=100&amount[lte]=1000&createdAt[gt]=2025-11-01

GET /api/v1/users?email[contains]=@example.com&role=user
```

**JavaScript Example**:
```javascript
function buildQueryParams(filters) {
  const params = new URLSearchParams();
  
  Object.entries(filters).forEach(([key, value]) => {
    if (typeof value === 'object') {
      Object.entries(value).forEach(([op, val]) => {
        params.append(`${key}[${op}]`, val);
      });
    } else {
      params.append(key, value);
    }
  });
  
  return params.toString();
}

// Usage
const filters = {
  status: 'active',
  emailVerified: true,
  createdAt: {
    gte: '2025-01-01',
    lt: '2025-12-31'
  }
};

const queryString = buildQueryParams(filters);
// Result: status=active&emailVerified=true&createdAt[gte]=2025-01-01&createdAt[lt]=2025-12-31

const response = await fetch(
  `https://api.suma.finance/api/v1/users?${queryString}`,
  { headers: { 'Authorization': `Bearer ${accessToken}` } }
);
```

### Sorting

**Query Parameter Format**:
```
?sort=field:direction
```

**Sort Direction**:
- `asc`: Ascending order
- `desc`: Descending order

**Single Field Sort**:
```
GET /api/v1/users?sort=createdAt:desc
```

**Multi-Field Sort**:
```
GET /api/v1/users?sort=lastName:asc,firstName:asc,createdAt:desc
```

**Default Sort Order**:
- If no `sort` parameter provided: `createdAt:desc` (newest first)

**Sortable Fields** (User endpoints):
- `createdAt`
- `updatedAt`
- `email`
- `firstName`
- `lastName`
- `lastLoginAt`

**JavaScript Example**:
```javascript
async function fetchSortedUsers(sortBy = 'createdAt', direction = 'desc') {
  const response = await fetch(
    `https://api.suma.finance/api/v1/users?sort=${sortBy}:${direction}`,
    { headers: { 'Authorization': `Bearer ${accessToken}` } }
  );
  
  return await response.json();
}

// Fetch users sorted by last name
const users = await fetchSortedUsers('lastName', 'asc');
```

### Combined Example: Pagination + Filtering + Sorting

**Request**:
```
GET /api/v1/users?page=1&limit=20&status=active&emailVerified=true&sort=createdAt:desc
```

**JavaScript Implementation**:
```javascript
async function fetchUsers({ page = 1, limit = 20, filters = {}, sort = 'createdAt:desc' }) {
  const params = new URLSearchParams({
    page,
    limit,
    sort
  });
  
  // Add filters
  Object.entries(filters).forEach(([key, value]) => {
    params.append(key, value);
  });
  
  const response = await fetch(
    `https://api.suma.finance/api/v1/users?${params}`,
    { headers: { 'Authorization': `Bearer ${accessToken}` } }
  );
  
  return await response.json();
}

// Usage
const result = await fetchUsers({
  page: 2,
  limit: 50,
  filters: {
    status: 'active',
    emailVerified: true
  },
  sort: 'lastName:asc'
});
```

---

## 8. Versioning Strategy

### API Version Scheme

**Format**: `v{major}`

**Current Version**: `v1`

**Examples**: `v1`, `v2`, `v3`

### Version Placement

**URL Path** (Primary Method):
```
https://api.suma.finance/api/v1/users
https://api.suma.finance/api/v2/users
```

**Not Supported**:
- ❌ Header versioning (`Accept: application/vnd.suma.v1+json`)
- ❌ Query parameter versioning (`?version=1`)

### Deprecation Policy

**Timeline**:
1. **Announcement**: New version announced 3 months before release
2. **Release**: New version released, old version marked as deprecated
3. **Deprecation Period**: 12 months of parallel support
4. **Sunset**: Old version disabled after 12 months

**Deprecation Headers**:
```
Deprecation: true
Sunset: Sat, 31 Dec 2026 23:59:59 GMT
Link: <https://docs.suma.finance/migrations/v1-to-v2>; rel="deprecation"
```

**Example Response from Deprecated Endpoint**:
```json
{
  "success": true,
  "data": {...},
  "warnings": [
    {
      "code": "DEPRECATED_VERSION",
      "message": "API v1 is deprecated and will be sunset on 2026-12-31. Please migrate to v2.",
      "migrationGuide": "https://docs.suma.finance/migrations/v1-to-v2"
    }
  ]
}
```

### Version Migration Guides

**Location**: `https://docs.suma.finance/migrations/`

**Available Guides**:
- v1 to v2 Migration Guide
- Breaking Changes Log
- Changelog

### Backwards Compatibility Strategy

**Within Major Version (v1.x)**:
- ✅ Additive changes (new fields, new endpoints)
- ✅ New optional parameters
- ✅ New response fields
- ❌ No breaking changes

**Breaking Changes (Requires New Major Version)**:
- Removing endpoints
- Removing request/response fields
- Changing field types
- Changing URL structure
- Changing authentication method
- Changing error response format

---

## 9. Rate Limiting and Throttling

### Rate Limit Policies

#### By Endpoint Type

| Endpoint Category | Rate Limit | Window | Scope |
|------------------|------------|--------|-------|
| Registration | 5 requests | 1 hour | Per IP |
| Login | 5 requests | 15 minutes | Per IP |
| Password Reset Request | 3 requests | 1 hour | Per IP |
| Email Verification | 10 requests | 1 hour | Per IP |
| Token Refresh | 20 requests | 1 hour | Per user |
| User Profile Read | 60 requests | 1 minute | Per user |
| User Profile Update | 10 requests | 1 hour | Per user |
| Account Deletion | 1 request | 1 day | Per user |

#### By User Tier (Future Enhancement)

| Tier | Rate Limit | Burst Limit |
|------|------------|-------------|
| Free | 100 req/min | 150 req/min |
| Premium | 500 req/min | 750 req/min |
| Enterprise | 2000 req/min | 3000 req/min |

### Rate Limit Headers

**Included in Every Response**:
```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1730548800
```

**Header Descriptions**:
- `X-RateLimit-Limit`: Maximum requests allowed in current window
- `X-RateLimit-Remaining`: Requests remaining in current window
- `X-RateLimit-Reset`: Unix timestamp when rate limit resets

**Example Response Headers**:
```
HTTP/1.1 200 OK
Content-Type: application/json
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1730548800
```

### Rate Limit Exceeded Response

**HTTP Status**: `429 Too Many Requests`

**Response**:
```json
{
  "success": false,
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Please try again later.",
    "requestId": "req_7Yx3mP9kL2Nq8vZ"
  }
}
```

**Headers**:
```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 0
X-RateLimit-Reset: 1730548860
Retry-After: 60
```

### Retry-After Header

**Format**: Seconds until retry is allowed

**Example**:
```
Retry-After: 60
```

**Client Handling**:
```javascript
async function fetchWithRateLimitHandling(url, options) {
  const response = await fetch(url, options);
  
  if (response.status === 429) {
    const retryAfter = parseInt(response.headers.get('Retry-After') || '60');
    console.log(`Rate limited. Waiting ${retryAfter} seconds...`);
    
    await new Promise(resolve => setTimeout(resolve, retryAfter * 1000));
    
    // Retry request
    return fetch(url, options);
  }
  
  return response;
}
```

### Burst Limits vs Sustained Limits

**Burst Limit**: Maximum requests in a 1-second window (prevents spam)
- Example: Max 10 requests per second

**Sustained Limit**: Maximum requests over longer window (prevents abuse)
- Example: Max 60 requests per minute

**Implementation**:
- Token bucket algorithm for burst control
- Sliding window for sustained limits

### Client-Side Rate Limit Management

**JavaScript Rate Limiter**:
```javascript
class RateLimiter {
  constructor(maxRequests, windowMs) {
    this.maxRequests = maxRequests;
    this.windowMs = windowMs;
    this.requests = [];
  }
  
  async throttle() {
    const now = Date.now();
    
    // Remove old requests outside window
    this.requests = this.requests.filter(time => now - time < this.windowMs);
    
    if (this.requests.length >= this.maxRequests) {
      const oldestRequest = this.requests[0];
      const waitTime = this.windowMs - (now - oldestRequest);
      
      console.log(`Rate limit reached. Waiting ${waitTime}ms...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
      
      return this.throttle(); // Retry
    }
    
    this.requests.push(now);
  }
}

// Usage
const loginRateLimiter = new RateLimiter(5, 15 * 60 * 1000); // 5 req per 15 min

async function login(email, password) {
  await loginRateLimiter.throttle();
  
  return fetch('/api/v1/auth/login', {
    method: 'POST',
    body: JSON.stringify({ email, password })
  });
}
```

---

## 10. Webhooks Documentation

**Note**: Webhooks are planned for future implementation. This section serves as a placeholder for webhook functionality related to user registration and authentication events.

### Planned Webhook Event Types

- `user.created`: User successfully registered
- `user.verified`: User verified email address
- `user.updated`: User profile updated
- `user.deleted`: User account deleted
- `user.suspended`: User account suspended
- `session.created`: User logged in
- `session.expired`: User session expired

### Planned Webhook Features

- Configurable webhook endpoints per event type
- HMAC-SHA256 signature verification
- Automatic retry with exponential backoff
- Webhook delivery logs and status monitoring
- Test webhook functionality in sandbox

**Documentation will be added in future API version.**

---

## 11. WebSocket/Real-Time API

**Note**: Real-time API via WebSocket is planned for future implementation for real-time notifications and session management.

### Planned Real-Time Features

- Real-time session expiration warnings
- Multi-device login notifications
- Account security alerts
- Real-time profile updates across devices

**Documentation will be added in future API version.**

---

## 12. GraphQL API Documentation

**Note**: GraphQL API is not currently planned for this version. The API uses RESTful architecture exclusively.

If GraphQL support is required in the future, it will be documented here.

---

## 13. API Security Documentation

### HTTPS Enforcement

**Protocol**: HTTPS only (TLS 1.2+)

**HTTP Requests**: Automatically redirected to HTTPS

**Certificate**: Valid SSL/TLS certificate from trusted CA

**HSTS Header**:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

### API Key Management

**Current Implementation**: JWT-based authentication (no static API keys)

**For Server-to-Server Integration** (Future):
- API keys with `sk_live_` or `sk_test_` prefix
- Stored in environment variables, never in code
- Rotatable via API or dashboard
- Scoped permissions per key

### OAuth 2.0 Flows

**Planned for Future Implementation**:
- Authorization Code Flow (for third-party apps)
- Client Credentials Flow (for server-to-server)

**Current**: Direct email/password authentication only

### CORS Policy

**Allowed Origins** (Development):
```
Access-Control-Allow-Origin: http://localhost:3000, http://localhost:5173
```

**Allowed Origins** (Production):
```
Access-Control-Allow-Origin: https://suma.finance, https://app.suma.finance
```

**Allowed Methods**:
```
Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS
```

**Allowed Headers**:
```
Access-Control-Allow-Headers: Authorization, Content-Type, Accept, X-Request-ID, X-Device-ID
```

**Credentials**:
```
Access-Control-Allow-Credentials: true
```

**Preflight Cache**:
```
Access-Control-Max-Age: 86400
```

### CSRF Protection

**Strategy**: Token-based authentication (JWT) is inherently CSRF-resistant

**Additional Protection**:
- `SameSite=Strict` cookie attribute for refresh tokens
- Origin/Referer header validation for state-changing operations
- Custom header requirement (`X-Requested-With: XMLHttpRequest`)

### Input Validation Requirements

**All Inputs Must Be Validated**:
- Type validation (string, number, boolean, email, UUID, etc.)
- Length validation (min/max length)
- Format validation (email, phone, URL, date, etc.)
- Range validation (min/max value for numbers)
- Pattern validation (regex for passwords, etc.)
- Whitelist validation (enum values)

**Example Validation Rules**:
```json
{
  "email": {
    "type": "string",
    "format": "email",
    "maxLength": 255,
    "required": true
  },
  "password": {
    "type": "string",
    "minLength": 8,
    "maxLength": 128,
    "pattern": "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$",
    "required": true
  },
  "phoneNumber": {
    "type": "string",
    "pattern": "^\\+[1-9]\\d{1,14}$"
  }
}
```

### SQL Injection Prevention

**Strategy**: Parameterized queries (prepared statements) only

**Forbidden**:
- ❌ String concatenation for SQL queries
- ❌ Dynamic SQL without parameterization

**Example (Secure)**:
```sql
-- Parameterized query (Go)
SELECT * FROM users WHERE email = $1
```

**Example (Insecure - NEVER DO THIS)**:
```sql
-- String concatenation - VULNERABLE
SELECT * FROM users WHERE email = '" + userInput + "'"
```

### XSS Prevention

**Server-Side**:
- Input sanitization for all user inputs
- Output encoding for HTML contexts
- Content-Security-Policy header

**Content-Security-Policy Header**:
```
Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';
```

**Client-Side**:
- React automatically escapes content (XSS protection)
- Avoid `dangerouslySetInnerHTML`
- Sanitize user-generated content before rendering

### Additional Security Headers

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: geolocation=(), microphone=(), camera=()
```

### Password Security

**Storage**: bcrypt hashing (cost factor 12)

**Requirements**:
- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit
- At least 1 special character (@$!%*?&)

**Validation Pattern**:
```regex
^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$
```

### Token Security

**Access Token**:
- Short-lived (1 hour)
- Stored in memory or sessionStorage (not localStorage)
- Transmitted via Authorization header only

**Refresh Token**:
- Longer-lived (7-30 days)
- Stored in HttpOnly, Secure, SameSite=Strict cookie
- Single-use (rotating refresh tokens)
- Revocable (stored in database)

**Token Revocation**:
- Logout revokes refresh token
- Password change revokes all tokens
- Account deletion revokes all tokens

---

## 14. Developer Onboarding

### Getting Started Guide

#### 1. Account Creation

**Sandbox Account** (For Testing):
1. Visit: `https://developers.suma.finance/sandbox`
2. Click "Create Sandbox Account"
3. Provide email and password
4. Verify email (instant verification in sandbox)
5. Access sandbox environment at `https://api-sandbox.suma.finance/api/v1`

**Production Account**:
1. Visit: `https://suma.finance/register`
2. Complete registration form
3. Verify email address
4. Complete KYC process (if required)
5. Access production API at `https://api.suma.finance/api/v1`

#### 2. API Key Generation

**Current**: JWT-based authentication (no API keys required)

**For Server-to-Server** (Future):
1. Log in to Developer Dashboard
2. Navigate to "API Keys"
3. Click "Create API Key"
4. Select permissions/scopes
5. Copy and securely store API key
6. Use in Authorization header: `Authorization: Bearer sk_live_...`

#### 3. First API Call Tutorial

**Step 1: Register a User**
```bash
curl -X POST https://api-sandbox.suma.finance/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!",
    "firstName": "Test",
    "lastName": "User",
    "acceptedTerms": true
  }'
```

**Step 2: Verify Email** (Use token from email)
```bash
curl -X POST https://api-sandbox.suma.finance/api/v1/auth/verify-email \
  -H "Content-Type: application/json" \
  -d '{
    "token": "evt_...",
    "email": "test@example.com"
  }'
```

**Step 3: Login**
```bash
curl -X POST https://api-sandbox.suma.finance/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'
```

**Step 4: Use Access Token**
```bash
curl -X GET https://api-sandbox.suma.finance/api/v1/users/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### 4. Quick Start Examples

**JavaScript (Node.js)**:
```javascript
const fetch = require('node-fetch');

const BASE_URL = 'https://api-sandbox.suma.finance/api/v1';

async function quickStart() {
  // 1. Register
  const registerResponse = await fetch(`${BASE_URL}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'TestPass123!',
      firstName: 'Test',
      lastName: 'User',
      acceptedTerms: true
    })
  });
  const registerData = await registerResponse.json();
  console.log('User registered:', registerData.data.userId);
  
  // 2. Login (skip email verification in sandbox)
  const loginResponse = await fetch(`${BASE_URL}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'test@example.com',
      password: 'TestPass123!'
    })
  });
  const loginData = await loginResponse.json();
  const accessToken = loginData.data.accessToken;
  console.log('Logged in, access token:', accessToken);
  
  // 3. Fetch user profile
  const profileResponse = await fetch(`${BASE_URL}/users/me`, {
    headers: { 'Authorization': `Bearer ${accessToken}` }
  });
  const profileData = await profileResponse.json();
  console.log('User profile:', profileData.data);
}

quickStart();
```

**Python**:
```python
import requests

BASE_URL = 'https://api-sandbox.suma.finance/api/v1'

# 1. Register
register_response = requests.post(f'{BASE_URL}/auth/register', json={
    'email': 'test@example.com',
    'password': 'TestPass123!',
    'firstName': 'Test',
    'lastName': 'User',
    'acceptedTerms': True
})
user_id = register_response.json()['data']['userId']
print(f'User registered: {user_id}')

# 2. Login
login_response = requests.post(f'{BASE_URL}/auth/login', json={
    'email': 'test@example.com',
    'password': 'TestPass123!'
})
access_token = login_response.json()['data']['accessToken']
print(f'Logged in: {access_token[:20]}...')

# 3. Fetch profile
profile_response = requests.get(
    f'{BASE_URL}/users/me',
    headers={'Authorization': f'Bearer {access_token}'}
)
profile = profile_response.json()['data']
print(f'User profile: {profile["email"]}')
```

### SDKs and Client Libraries

#### Official SDKs (Planned)

**JavaScript/TypeScript SDK**:
```bash
npm install @suma/finance-sdk
```

```javascript
import { SumaClient } from '@suma/finance-sdk';

const suma = new SumaClient({
  environment: 'sandbox', // or 'production'
  apiKey: 'sk_test_...' // For server-side only
});

// Register user
const user = await suma.auth.register({
  email: 'user@example.com',
  password: 'SecurePass123!',
  firstName: 'John',
  lastName: 'Doe',
  acceptedTerms: true
});

// Login
const session = await suma.auth.login({
  email: 'user@example.com',
  password: 'SecurePass123!'
});

// Auto-handles token refresh
const profile = await suma.users.me();
```

**Python SDK**:
```bash
pip install suma-finance
```

```python
from suma import SumaClient

suma = SumaClient(
    environment='sandbox',
    api_key='sk_test_...'
)

# Register
user = suma.auth.register(
    email='user@example.com',
    password='SecurePass123!',
    first_name='John',
    last_name='Doe',
    accepted_terms=True
)

# Login
session = suma.auth.login(
    email='user@example.com',
    password='SecurePass123!'
)

# Fetch profile
profile = suma.users.me()
```

**Go SDK**:
```bash
go get github.com/suma-finance/suma-go
```

```go
import "github.com/suma-finance/suma-go"

client := suma.NewClient(&suma.Config{
    Environment: suma.Sandbox,
    APIKey: "sk_test_...",
})

// Register
user, err := client.Auth.Register(&suma.RegisterRequest{
    Email: "user@example.com",
    Password: "SecurePass123!",
    FirstName: "John",
    LastName: "Doe",
    AcceptedTerms: true,
})

// Login
session, err := client.Auth.Login(&suma.LoginRequest{
    Email: "user@example.com",
    Password: "SecurePass123!",
})

// Fetch profile
profile, err := client.Users.Me()
```

### Testing and Sandbox

#### Sandbox Environment

**Base URL**: `https://api-sandbox.suma.finance/api/v1`

**Features**:
- Identical to production API
- No real data or transactions
- Email verification disabled (auto-verified)
- Relaxed rate limits
- Test webhooks
- Reset data daily

**Test Accounts**:
```json
{
  "email": "test-user@suma-sandbox.com",
  "password": "SandboxPass123!",
  "role": "user"
}
```

```json
{
  "email": "test-admin@suma-sandbox.com",
  "password": "SandboxPass123!",
  "role": "admin"
}
```

#### Postman Collection

**Download**: `https://developers.suma.finance/postman/suma-finance-api.json`

**Import to Postman**:
1. Click "Import" in Postman
2. Paste URL: `https://developers.suma.finance/postman/suma-finance-api.json`
3. Select "Suma Finance API" collection
4. Configure environment variables:
   - `baseUrl`: `https://api-sandbox.suma.finance/api/v1`
   - `accessToken`: (populated after login)

**Pre-configured Requests**:
- Register User
- Verify Email
- Login
- Refresh Token
- Get User Profile
- Update User Profile
- Change Password
- Logout

#### OpenAPI Spec Download

**OpenAPI 3.0.3 Specification**:

**Download URL**: `https://api.suma.finance/api/v1/openapi.json`

**Import to Tools**:
- Postman: Import → Link → Paste URL
- Insomnia: Import/Export → From URL
- Swagger Editor: File → Import URL
- Code Generators: `openapi-generator-cli generate -i <url>`

---

## 15. API Monitoring and Analytics

### API Health Status Page

**URL**: `https://status.suma.finance`

**Monitored Services**:
- API Gateway
- Authentication Service
- Database
- Email Service
- Rate Limiter

**Status Indicators**:
- 🟢 Operational
- 🟡 Degraded Performance
- 🔴 Partial Outage
- ⚫ Major Outage

### Performance Metrics

**Public Metrics** (https://status.suma.finance):
- API Uptime (30-day, 90-day)
- Average Response Time (p50, p95, p99)
- Error Rate
- Incident History

**Example Metrics**:
```json
{
  "uptime30d": 99.98,
  "uptime90d": 99.95,
  "responseTime": {
    "p50": 85,
    "p95": 250,
    "p99": 450
  },
  "errorRate": 0.02,
  "lastIncident": "2025-10-15T10:30:00Z"
}
```

### Usage Analytics (For Authenticated Users)

**Dashboard**: `https://developers.suma.finance/analytics`

**Available Metrics**:
- Total API calls (by endpoint)
- Success rate
- Error rate (by error code)
- Average response time
- Rate limit hits
- Top endpoints
- Usage over time (hourly, daily, weekly)

### Deprecation Notices

**Location**: 
- API response warnings
- Email notifications
- Status page announcements
- Developer dashboard

**Example Deprecation Warning**:
```json
{
  "success": true,
  "data": {...},
  "warnings": [
    {
      "code": "DEPRECATED_VERSION",
      "message": "API v1 will be sunset on 2026-12-31. Migrate to v2.",
      "migrationGuide": "https://docs.suma.finance/migrations/v1-to-v2",
      "sunsetDate": "2026-12-31T23:59:59Z"
    }
  ]
}
```

### Changelog and Release Notes

**Location**: `https://docs.suma.finance/changelog`

**Format**:
```markdown
## [1.2.0] - 2025-11-15

### Added
- New endpoint: `GET /api/v1/users/me/sessions` for viewing active sessions
- Support for multi-factor authentication (MFA)

### Changed
- Increased password complexity requirements
- Extended refresh token lifetime to 30 days (with rememberMe=true)

### Fixed
- Fixed rate limit counter not resetting properly
- Fixed email verification token expiration handling

### Deprecated
- `GET /api/v1/auth/status` - Use `GET /api/v1/users/me` instead

### Security
- Upgraded JWT library to v5.2.0
- Implemented HSTS preload
```

---

## 16. Best Practices and Guidelines

### API Design Principles

1. **Resource-Oriented**: URLs represent resources, not actions
   - ✅ `POST /api/v1/users` (create user)
   - ❌ `POST /api/v1/createUser`

2. **Stateless**: Each request contains all necessary information
   - Include authentication in every request
   - No server-side session state

3. **Consistent Naming**: Use consistent conventions
   - Lowercase URLs
   - Plural resource names
   - Hyphens for multi-word resources

4. **Proper HTTP Methods**: Use correct method for each operation
   - GET: Read
   - POST: Create
   - PUT: Replace
   - PATCH: Partial update
   - DELETE: Remove

5. **Idempotency**: GET, PUT, DELETE should be idempotent
   - Multiple identical requests = same result as single request

### Idempotency for Write Operations

**Idempotent Methods** (Safe to Retry):
- GET
- PUT
- DELETE

**Non-Idempotent Methods** (Require Idempotency Keys):
- POST

**Implementing Idempotency Keys**:
```javascript
const idempotencyKey = `${userId}_${operation}_${Date.now()}_${crypto.randomUUID()}`;

const response = await fetch('https://api.suma.finance/api/v1/transactions', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'Idempotency-Key': idempotencyKey
  },
  body: JSON.stringify({ amount: 100, currency: 'EUR' })
});
```

**Server Behavior**:
- First request: Process normally, store result with key (24-hour TTL)
- Duplicate request (same key + same body): Return cached result (200 OK)
- Duplicate request (same key + different body): Return 409 Conflict

### Handling Concurrent Updates

#### Optimistic Locking with ETags

**Request**:
```javascript
// 1. Fetch resource with ETag
const getResponse = await fetch('https://api.suma.finance/api/v1/users/me');
const user = await getResponse.json();
const etag = getResponse.headers.get('ETag');

// 2. Update resource with If-Match header
const updateResponse = await fetch('https://api.suma.finance/api/v1/users/me', {
  method: 'PATCH',
  headers: {
    'Authorization': `Bearer ${accessToken}`,
    'Content-Type': 'application/json',
    'If-Match': etag
  },
  body: JSON.stringify({ firstName: 'Jane' })
});

if (updateResponse.status === 412) {
  // Precondition Failed - resource was modified by another request
  console.error('Resource was modified. Please refresh and try again.');
}
```

**Response Headers**:
```
ETag: "v1-usr_2Nq8vYZ1wX3mP9kL-1730548800"
```

**Conflict Response (412 Precondition Failed)**:
```json
{
  "success": false,
  "error": {
    "code": "PRECONDITION_FAILED",
    "message": "Resource was modified by another request. Please refresh and try again.",
    "currentEtag": "v1-usr_2Nq8vYZ1wX3mP9kL-1730549000"
  }
}
```

### Long-Running Operations

**Approach 1: Synchronous with Timeout**
- Simple operations (<30 seconds)
- Return result immediately

**Approach 2: Asynchronous with Polling**
```javascript
// 1. Start operation
const startResponse = await fetch('https://api.suma.finance/api/v1/exports', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${accessToken}` },
  body: JSON.stringify({ type: 'user_data' })
});
const { operationId } = await startResponse.json();

// Response: 202 Accepted
{
  "success": true,
  "data": {
    "operationId": "op_3Kx9mP2nQ8vY1wZ",
    "status": "processing",
    "statusUrl": "/api/v1/operations/op_3Kx9mP2nQ8vY1wZ"
  }
}

// 2. Poll for status
async function pollOperation(operationId) {
  while (true) {
    const statusResponse = await fetch(
      `https://api.suma.finance/api/v1/operations/${operationId}`,
      { headers: { 'Authorization': `Bearer ${accessToken}` } }
    );
    const status = await statusResponse.json();
    
    if (status.data.status === 'completed') {
      return status.data.result;
    } else if (status.data.status === 'failed') {
      throw new Error(status.data.error);
    }
    
    await new Promise(resolve => setTimeout(resolve, 2000)); // Poll every 2s
  }
}

const result = await pollOperation(operationId);
```

**Approach 3: Webhooks** (Future)
- Register webhook URL
- Receive notification when operation completes

### Bulk Operations

**Bulk Create** (Future Enhancement):
```javascript
POST /api/v1/users/bulk

{
  "users": [
    { "email": "user1@example.com", "password": "...", ... },
    { "email": "user2@example.com", "password": "...", ... }
  ]
}

Response:
{
  "success": true,
  "data": {
    "created": 2,
    "failed": 0,
    "results": [
      { "email": "user1@example.com", "userId": "usr_...", "status": "created" },
      { "email": "user2@example.com", "userId": "usr_...", "status": "created" }
    ]
  }
}
```

**Partial Success Handling**:
```json
{
  "success": true,
  "data": {
    "created": 1,
    "failed": 1,
    "results": [
      { "email": "user1@example.com", "userId": "usr_...", "status": "created" },
      { 
        "email": "user2@example.com", 
        "status": "failed", 
        "error": {
          "code": "EMAIL_ALREADY_EXISTS",
          "message": "Email already exists"
        }
      }
    ]
  }
}
```

### File Upload/Download

**File Upload** (Avatar Upload Example - Future):
```javascript
POST /api/v1/users/me/avatar

Content-Type: multipart/form-data

const formData = new FormData();
formData.append('avatar', fileBlob, 'avatar.jpg');

const response = await fetch('https://api.suma.finance/api/v1/users/me/avatar', {
  method: 'POST',
  headers: { 'Authorization': `Bearer ${accessToken}` },
  body: formData
});

Response:
{
  "success": true,
  "data": {
    "avatarUrl": "https://cdn.suma.finance/avatars/usr_2Nq8vYZ1wX3mP9kL.jpg",
    "size": 102400,
    "mimeType": "image/jpeg"
  }
}
```

**File Download** (Export Data - Future):
```javascript
GET /api/v1/users/me/export

Response Headers:
Content-Type: application/json
Content-Disposition: attachment; filename="user_data_2025-11-02.json"

const response = await fetch('https://api.suma.finance/api/v1/users/me/export', {
  headers: { 'Authorization': `Bearer ${accessToken}` }
});

const blob = await response.blob();
const url = window.URL.createObjectURL(blob);
const a = document.createElement('a');
a.href = url;
a.download = 'user_data.json';
a.click();
```

---

## 17. Documentation Generation Architecture

### OpenAPI/Swagger Specification

**Specification Version**: OpenAPI 3.0.3

**Location**: `https://api.suma.finance/api/v1/openapi.json`

**Generation Method**: Code-first (generated from code annotations)

**Example OpenAPI Spec** (Partial):
```yaml
openapi: 3.0.3
info:
  title: SUMA Finance API
  version: 1.0.0
  description: User registration and authentication API for SUMA Finance
  contact:
    name: API Support
    email: api-support@suma.finance
    url: https://developers.suma.finance/support
  license:
    name: Proprietary
    url: https://suma.finance/terms

servers:
  - url: https://api.suma.finance/api/v1
    description: Production
  - url: https://api-sandbox.suma.finance/api/v1
    description: Sandbox

paths:
  /auth/register:
    post:
      summary: Register new user
      operationId: registerUser
      tags:
        - Authentication
      requestBody:
        required: true
        content:
          application/json:
            schema:
              $ref: '#/components/schemas/RegisterUserRequest'
      responses:
        '201':
          description: User registered successfully
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/RegisterUserResponse'
        '400':
          description: Validation error
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'
        '409':
          description: Email already exists
          content:
            application/json:
              schema:
                $ref: '#/components/schemas/ErrorResponse'

components:
  schemas:
    RegisterUserRequest:
      type: object
      required:
        - email
        - password
        - firstName
        - lastName
        - acceptedTerms
      properties:
        email:
          type: string
          format: email
          maxLength: 255
        password:
          type: string
          minLength: 8
          maxLength: 128
          pattern: '^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$'
        firstName:
          type: string
          minLength: 1
          maxLength: 100
        lastName:
          type: string
          minLength: 1
          maxLength: 100
        phoneNumber:
          type: string
          pattern: '^\+[1-9]\d{1,14}$'
        acceptedTerms:
          type: boolean
          const: true

  securitySchemes:
    bearerAuth:
      type: http
      scheme: bearer
      bearerFormat: JWT

security:
  - bearerAuth: []
```

### Schema Validation

**JSON Schema Validation**: All request/response schemas validated against JSON Schema Draft 2020-12

**Validation Tools**:
- Server-side: Pydantic (Python) / go-playground/validator (Go)
- Client-side: Ajv (JavaScript)
- Testing: OpenAPI Validator

### Documentation Auto-Generation

**Source**: Code annotations (Go struct tags, Python Pydantic models)

**Example (Go)**:
```go
// RegisterUserRequest represents user registration data
// @Description User registration request
type RegisterUserRequest struct {
    // User's email address (must be unique)
    // @example user@example.com
    Email string `json:"email" binding:"required,email,max=255"`
    
    // Password (min 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char)
    // @example SecurePass123!
    Password string `json:"password" binding:"required,min=8,max=128,password"`
    
    // User's first name
    // @example John
    FirstName string `json:"firstName" binding:"required,min=1,max=100"`
    
    // User's last name
    // @example Doe
    LastName string `json:"lastName" binding:"required,min=1,max=100"`
    
    // Phone number in E.164 format
    // @example +351912345678
    PhoneNumber string `json:"phoneNumber,omitempty" binding:"omitempty,e164"`
    
    // Must accept terms and conditions
    // @example true
    AcceptedTerms bool `json:"acceptedTerms" binding:"required,eq=true"`
}
```

**Generation Command**:
```bash
# Generate OpenAPI spec from code
swag init --parseDependency --parseInternal --parseDepth 2

# Validate generated spec
openapi-generator-cli validate -i openapi.json
```

### Documentation Tooling

#### Swagger UI

**URL**: `https://docs.suma.finance/swagger-ui`

**Features**:
- Interactive API documentation
- "Try it out" functionality
- Request/response examples
- Schema validation
- Authentication support

**Configuration**:
```javascript
SwaggerUIBundle({
  url: 'https://api.suma.finance/api/v1/openapi.json',
  dom_id: '#swagger-ui',
  deepLinking: true,
  presets: [
    SwaggerUIBundle.presets.apis,
    SwaggerUIStandalonePreset
  ],
  plugins: [
    SwaggerUIBundle.plugins.DownloadUrl
  ],
  layout: "StandaloneLayout",
  defaultModelsExpandDepth: 1,
  defaultModelExpandDepth: 3,
  displayRequestDuration: true,
  filter: true,
  tryItOutEnabled: true
})
```

#### Redoc

**URL**: `https://docs.suma.finance/redoc`

**Features**:
- Clean, readable documentation
- Three-column layout
- Code samples in multiple languages
- Search functionality
- Printable documentation

**Configuration**:
```html
<!DOCTYPE html>
<html>
<head>
  <title>SUMA Finance API Documentation</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
  <style>
    body { margin: 0; padding: 0; }
  </style>
</head>
<body>
  <redoc spec-url='https://api.suma.finance/api/v1/openapi.json'></redoc>
  <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"></script>
</body>
</html>
```

#### Postman/Insomnia Collections

**Postman Collection**: `https://developers.suma.finance/postman/suma-finance-api.json`

**Auto-Generated From**: OpenAPI specification

**Generation**:
```bash
openapi2postmanv2 -s openapi.json -o postman-collection.json -p
```

### Documentation CI/CD

**Pipeline**:
1. Code changes pushed to repository
2. CI runs code annotation parser
3. OpenAPI spec generated from annotations
4. Spec validated against OpenAPI 3.0.3 schema
5. Swagger UI and Redoc deployed to documentation portal
6. Postman collection generated and published
7. SDK documentation updated

**GitHub Actions Example**:
```yaml
name: Generate API Documentation

on:
  push:
    branches: [main]
    paths:
      - 'internal/**/*.go'
      - 'docs/openapi.yaml'

jobs:
  generate-docs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Install Swagger CLI
        run: npm install -g @apidevtools/swagger-cli
      
      - name: Generate OpenAPI spec
        run: swag init
      
      - name: Validate OpenAPI spec
        run: swagger-cli validate docs/openapi.json
      
      - name: Deploy to documentation portal
        run: |
          aws s3 cp docs/openapi.json s3://docs.suma.finance/
          aws cloudfront create-invalidation --distribution-id ${{ secrets.CF_DIST_ID }}
```

### Versioned Documentation

**URL Structure**:
- Latest: `https://docs.suma.finance/`
- v1: `https://docs.suma.finance/v1/`
- v2: `https://docs.suma.finance/v2/` (future)

**Version Switcher**: Dropdown in documentation UI to switch between versions

---

## 18. API Governance

### API Design Review Process

**Required for**:
- New endpoints
- Breaking changes
- Deprecations

**Review Checklist**:
- ✅ Follows RESTful conventions
- ✅ Consistent naming
- ✅ Proper HTTP methods and status codes
- ✅ Comprehensive error handling
- ✅ Input validation
- ✅ Security review (authentication, authorization, input sanitization)
- ✅ Rate limiting configured
- ✅ Documentation complete
- ✅ Tests written

**Approval Required From**:
- API architect
- Security team
- Backend lead

### Breaking Change Policy

**Definition of Breaking Change**:
- Removing endpoints
- Removing request/response fields
- Changing field types
- Changing field semantics
- Changing authentication method
- Changing error response format
- Renaming fields

**Breaking Change Process**:
1. Announce breaking change 3 months before release
2. Deprecate old version
3. Release new major version (v2)
4. Maintain old version for 12 months
5. Sunset old version after deprecation period

### Deprecation Timeline

**Timeline**:
- **T-3 months**: Deprecation announced
- **T-0**: New version released, old version deprecated
- **T+6 months**: Deprecation warnings in responses
- **T+9 months**: Increased deprecation warnings
- **T+12 months**: Old version sunset

**Communication Channels**:
- Email to registered developers
- API response warnings
- Status page announcements
- Documentation banners
- Changelog

### API Lifecycle Management

**Stages**:
1. **Development**: Internal development and testing
2. **Alpha**: Limited external testing (invite-only)
3. **Beta**: Public testing (unstable, may change)
4. **Stable**: Production-ready (backward compatible within major version)
5. **Deprecated**: Marked for sunset (12-month support)
6. **Sunset**: Disabled (returns 410 Gone)

**Version Status Endpoint**:
```
GET /api/v1/status

Response:
{
  "version": "1.0.0",
  "status": "stable",
  "deprecationDate": null,
  "sunsetDate": null,
  "latestVersion": "1.0.0"
}
```

### Consistency Across Endpoints

**Enforced Standards**:
- Consistent response format (success/error wrapper)
- Consistent error response format
- Consistent pagination metadata
- Consistent timestamp format (ISO 8601)
- Consistent field naming (camelCase)
- Consistent HTTP status codes
- Consistent authentication method
- Consistent rate limit headers

**Linting and Validation**:
- Spectral (OpenAPI linter)
- Custom API governance rules
- Automated checks in CI/CD

---

## Appendix: Complete Endpoint Reference

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/api/v1/auth/register` | Register new user | No |
| POST | `/api/v1/auth/verify-email` | Verify email address | No |
| POST | `/api/v1/auth/login` | Login with credentials | No |
| POST | `/api/v1/auth/refresh` | Refresh access token | Refresh Token |
| POST | `/api/v1/auth/logout` | Logout and invalidate tokens | Yes |
| POST | `/api/v1/auth/password-reset/request` | Request password reset | No |
| POST | `/api/v1/auth/password-reset/confirm` | Confirm password reset | No |

### User Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/api/v1/users/me` | Get current user profile | Yes |
| PATCH | `/api/v1/users/me` | Update user profile | Yes |
| PUT | `/api/v1/users/me/password` | Change password | Yes |
| DELETE | `/api/v1/users/me` | Delete account | Yes |

---

## Summary

This API Documentation Architecture provides comprehensive guidance for implementing, integrating, and maintaining the User Registration & Authentication API for SUMA Finance. It covers:

- ✅ RESTful API design standards and conventions
- ✅ Complete endpoint documentation with examples
- ✅ Request/response schemas and validation rules
- ✅ JWT-based authentication and authorization
- ✅ Comprehensive error handling and error codes
- ✅ Pagination, filtering, and sorting strategies
- ✅ API versioning and deprecation policies
- ✅ Rate limiting and security measures
- ✅ Developer onboarding and SDKs
- ✅ OpenAPI/Swagger documentation generation
- ✅ API governance and best practices

**Next Steps**:
1. Review and approve API design
2. Implement backend endpoints (Gate 2)
3. Generate OpenAPI specification
4. Set up Swagger UI and Redoc
5. Implement authentication and authorization
6. Configure rate limiting
7. Write integration tests
8. Deploy to sandbox environment
9. Prepare developer documentation
10. Launch API v1

---

**Document Version**: 1.0  
**Last Updated**: 2025-11-02  
**Maintained By**: SUMA Finance API Team