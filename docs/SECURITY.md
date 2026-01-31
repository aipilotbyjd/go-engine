# LinkFlow Go Engine - Security Guide

This document outlines the security measures implemented in the LinkFlow Go Engine and provides guidance for secure deployment.

## Table of Contents
1. [Security Fixes Applied](#security-fixes-applied)
2. [Authentication](#authentication)
3. [Authorization](#authorization)
4. [Sandbox Security](#sandbox-security)
5. [Cryptographic Standards](#cryptographic-standards)
6. [Configuration Security](#configuration-security)
7. [HTTP Security](#http-security)
8. [Production Checklist](#production-checklist)

---

## Security Fixes Applied

The following critical security vulnerabilities have been addressed:

### 1. JWT Token Validation (CRITICAL)
**Location:** `internal/frontend/interceptor/auth.go`

**Before:** Accepted ANY non-empty token string as valid
**After:** Implements full HMAC-SHA256 signature verification with:
- Token structure validation (header.payload.signature)
- Cryptographic signature verification using constant-time comparison
- Expiration time validation
- Not-before time validation
- Issuer validation (configurable)
- Audience validation (configurable)

### 2. JWT Library Security (CRITICAL)
**Location:** `internal/security/authn/jwt.go`

**Before:** Signature validation was TODO/placeholder
**After:** 
- Full HS256 (HMAC-SHA256) signature verification
- Explicit rejection of "none" algorithm (JWT security vulnerability)
- Proper base64url decoding (RFC 4648)
- Removed insecure query parameter token extraction

### 3. Sandbox Isolation (CRITICAL)
**Location:** `internal/sandbox/sandbox.go`

**Before:** 
- Bash scripts inherited `os.Environ()` (leaking secrets)
- No environment variable sanitization
- Limited container security options

**After:**
- Minimal, hardcoded safe environment for all sandboxed processes
- Blocklist of dangerous environment variables (`LD_PRELOAD`, `BASH_ENV`, etc.)
- Validation of user-provided environment variable names
- Enhanced Docker container security:
  - `--read-only` filesystem
  - `--cap-drop ALL`
  - `--security-opt no-new-privileges:true`
  - `--pids-limit 100`
  - `--ulimit nofile=100:200`
  - Secure tmpfs with noexec

### 4. Cryptographically Secure Random Generation (HIGH)
**Location:** `internal/frontend/handler/http.go`

**Before:** Used sequential character assignment (always "abcdefghijklmnop")
**After:** Uses `crypto/rand` for cryptographically secure random strings

### 5. API Key Hashing (HIGH)
**Location:** `internal/security/authn/jwt.go`

**Before:** API keys stored/compared in plaintext
**After:** SHA-256 hashing for secure storage and comparison

### 6. Required Secrets (HIGH)
**Location:** `docker-compose.yml`

**Before:** Weak fallback defaults for JWT_SECRET and LINKFLOW_SECRET
**After:** Required environment variables with clear error messages

### 7. Database SSL (HIGH)
**Location:** `docker-compose.yml`

**Before:** `sslmode=disable`
**After:** `sslmode=prefer` (upgrade to `sslmode=require` for production)

### 8. HTTP Security Headers (MEDIUM)
**Location:** `internal/frontend/handler/http.go`

Added security middleware with:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `X-XSS-Protection: 1; mode=block`
- `Cache-Control: no-store, no-cache, must-revalidate`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `Referrer-Policy: strict-origin-when-cross-origin`

### 9. Request Body Size Limits (MEDIUM)
**Location:** `internal/frontend/handler/http.go`

Added 1MB request body limit to prevent memory exhaustion attacks.

---

## Authentication

### JWT Authentication
The engine uses JWT (JSON Web Token) for API authentication:

```go
// Configuration
AuthConfig{
    SecretKey: "your-32+-char-secret",  // REQUIRED: min 32 chars
    Issuer:    "linkflow-api",          // Optional: validate issuer
    Audience:  "linkflow-engine",       // Optional: validate audience
}
```

**Token Format:**
```
header.payload.signature
```

**Supported Algorithms:**
- HS256 (HMAC-SHA256) - Recommended
- RS256 (RSA-SHA256) - Planned

**Security Features:**
- Constant-time signature comparison (timing attack prevention)
- Automatic expiration validation
- Issuer/audience validation
- "none" algorithm explicitly rejected

### API Key Authentication
API keys are supported for service-to-service authentication:

```go
// Keys are hashed before storage
hash := sha256.Sum256([]byte(rawApiKey))
storedKey := hex.EncodeToString(hash[:])
```

---

## Authorization

The engine implements both RBAC and ABAC:

### Role-Based Access Control (RBAC)
**Location:** `internal/security/authz/rbac.go`

Built-in roles:
- `owner` - Full access (`*:*`)
- `admin` - Workflows, executions, credentials, variables
- `editor` - Read/write workflows, execute, read variables
- `viewer` - Read-only access
- `executor` - Execute workflows only

### Attribute-Based Access Control (ABAC)
For fine-grained permission control based on:
- User attributes
- Resource attributes
- Environmental conditions

---

## Sandbox Security

The sandbox executes untrusted code with the following isolation measures:

### Process Mode (Node.js, Python, Bash)
- **No parent environment inheritance** - Scripts receive a minimal environment
- **Blocked dangerous variables**: `LD_PRELOAD`, `LD_LIBRARY_PATH`, `BASH_ENV`, `IFS`, etc.
- **Validated environment keys** - Only alphanumeric + underscore allowed
- **Memory limits** - Default 128MB
- **Timeout enforcement** - Default 30 seconds

### Container Mode (Docker)
Full isolation with security options:
```bash
docker run --rm \
  --network none \                    # No network access
  --read-only \                       # Read-only root filesystem
  --cap-drop ALL \                    # Drop all capabilities
  --security-opt no-new-privileges \  # Prevent privilege escalation
  --pids-limit 100 \                  # Limit processes
  --ulimit nofile=100:200 \           # Limit open files
  --memory <limit> \                  # Memory limit
  --cpus <limit> \                    # CPU limit
  --tmpfs /tmp:rw,noexec,nosuid,size=64m  # Secure temporary filesystem
```

---

## Cryptographic Standards

| Purpose | Algorithm | Key Size | Notes |
|---------|-----------|----------|-------|
| JWT Signing | HMAC-SHA256 | 256-bit | Min 32-char secret |
| Password Hashing | PBKDF2-SHA256 | 256-bit | 100,000 iterations |
| Data Encryption | AES-256-GCM | 256-bit | Authenticated encryption |
| Key Derivation | PBKDF2-SHA256 | 256-bit | 10,000 iterations |
| Random Generation | crypto/rand | N/A | OS entropy source |
| Callback Signing | HMAC-SHA256 | 256-bit | For Laravel callbacks |

---

## Configuration Security

### Required Environment Variables
```bash
# Generate secure secrets:
# openssl rand -base64 32

JWT_SECRET=<min-32-char-secure-random-string>
LINKFLOW_SECRET=<secure-random-string-for-callbacks>
POSTGRES_PASSWORD=<secure-database-password>
```

### Database Security
```bash
# Development (with SSL preference)
DATABASE_URL=postgres://...?sslmode=prefer

# Production (require SSL)
DATABASE_URL=postgres://...?sslmode=require

# High Security (verify certificate)
DATABASE_URL=postgres://...?sslmode=verify-full&sslrootcert=/path/to/ca.pem
```

---

## HTTP Security

All API endpoints are protected with:

1. **Security Headers** - Prevent XSS, clickjacking, MIME sniffing
2. **Body Size Limits** - 1MB maximum to prevent DoS
3. **Rate Limiting** - Per-namespace rate limits
4. **Authentication** - JWT or API key required
5. **Authorization** - RBAC permission checks

---

## Production Checklist

Before deploying to production:

### Secrets
- [ ] `JWT_SECRET` is a cryptographically random 32+ character string
- [ ] `LINKFLOW_SECRET` is a cryptographically random string
- [ ] `POSTGRES_PASSWORD` is changed from default
- [ ] Secrets are managed via a secret management solution (Vault, AWS Secrets Manager, etc.)

### Database
- [ ] SSL is enabled (`sslmode=require` or `sslmode=verify-full`)
- [ ] Database user has minimal required permissions
- [ ] Database is not publicly accessible

### Network
- [ ] All services are behind a reverse proxy with TLS
- [ ] TLS 1.2+ is enforced
- [ ] Internal services are not exposed publicly
- [ ] Network policies restrict inter-service communication

### Containers
- [ ] Images are scanned for vulnerabilities
- [ ] Non-root users are used where possible
- [ ] Read-only root filesystems are enabled
- [ ] Resource limits are configured

### Monitoring
- [ ] Audit logging is enabled and persisted
- [ ] Failed authentication attempts are monitored
- [ ] Anomaly detection is in place
- [ ] Security alerts are configured

### Updates
- [ ] Dependency update process is established
- [ ] Security advisories are monitored
- [ ] Incident response plan is documented

---

## Security Contact

For security vulnerabilities, please contact: security@linkflow.com

Do NOT create public GitHub issues for security vulnerabilities.
