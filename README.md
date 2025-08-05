# TestApp - Auth0 Authentication API

This is a .NET 9 Web API project that demonstrates Auth0 authentication integration with PKCE (Proof Key for Code Exchange) flow and enhanced Swagger UI integration.

## Features

- ✅ **Auth0 JWT Bearer Authentication** - Secure API endpoints with Auth0 tokens
- ✅ **PKCE Authentication Flow** - Secure OAuth 2.0 flow with code challenge/verifier
- ✅ **Interactive Swagger UI** - One-click Auth0 login directly from Swagger
- ✅ **Automatic Token Injection** - Tokens automatically set after authentication
- ✅ **Session Management** - Secure OAuth state and token storage
- ✅ **Real-time Debugging** - Console logging for authentication flow
- ✅ **Token Retrieval API** - Programmatic access to current tokens
- ✅ **Modern UI Design** - Enhanced button styles and user experience
- ✅ **CORS Configuration** - Cross-origin request support

## Setup Instructions

### 1. Auth0 Configuration

1. **Create an Auth0 account** at [https://auth0.com](https://auth0.com)

2. **Create a new application:**
   - Go to **Applications > Create Application**
   - Choose **"Single Page Application"** (for PKCE flow)
   - Note down the **Domain**, **Client ID**, and **Client Secret**

3. **Configure Application Settings:**
   - **Allowed Callback URLs**: `https://localhost:5001/auth/callback`
   - **Allowed Web Origins**: `https://localhost:5001`
   - **Allowed Origins (CORS)**: `https://localhost:5001`

4. **Create an API:**
   - Go to **APIs > Create API**
   - Set a name and identifier (audience)
   - Note down the **API identifier**

5. **Update Configuration Files:**

   **`appsettings.json`:**
   ```json
   {
     "Auth0": {
       "Domain": "your-auth0-domain.auth0.com",
       "ClientId": "your-client-id",
       "ClientSecret": "your-client-secret",
       "Audience": "your-api-identifier"
     },
     "Cors": {
       "PolicyName": "AllowSwaggerOrigins",
       "AllowedOrigins": ["https://localhost:5001"],
       "AllowedMethods": ["*"],
       "AllowedHeaders": ["*"],
       "AllowCredentials": true
     }
   }
   ```

   **`appsettings.Development.json`:**
   ```json
   {
     "Auth0": {
       "Domain": "your-auth0-domain.auth0.com",
       "ClientId": "your-client-id",
       "ClientSecret": "your-client-secret",
       "Audience": "your-api-identifier"
     }
   }
   ```

### 2. Running the Application

```bash
dotnet run
```

The application will start on `https://localhost:5001` (or the port shown in the console).

## Available Endpoints

### Public Endpoints
- `GET /health` - Health check endpoint
- `GET /api/test/public` - Public test endpoint (no authentication required)

### Authentication Endpoints
- `GET /auth/login` - Initiates Auth0 PKCE authentication flow
- `GET /auth/callback` - Handles Auth0 callback and token exchange
- `GET /api/auth/token` - Retrieves current session token (JSON format)

### Protected Endpoints (Require Authentication)
- `GET /api/test/protected` - Protected endpoint requiring valid JWT token
- `GET /api/test/user` - Returns user information and claims from JWT token

### Swagger Documentation
- Navigate to `https://localhost:5001/swagger` to view the interactive API documentation

## Authentication Methods

### Method 1: Swagger UI Integration (Recommended)

1. **Open Swagger UI** at `https://localhost:5001/swagger`
2. **Click "🔐 Login with Auth0"** in the Authentication section
3. **Complete Auth0 login** (redirects to your Auth0 domain)
4. **Return automatically** with token set in Authorization header
5. **Test protected endpoints** immediately

### Method 2: Manual Token Retrieval

1. **Login via Swagger** or visit `/auth/login` directly
2. **Click "📋 Get Current Token"** or visit `/api/auth/token`
3. **Copy the BearerToken** value from the JSON response
4. **Use "Authorize" button** in Swagger UI to set the token manually

### Method 3: Direct API Calls

#### Get Access Token (Client Credentials - for M2M apps)
```bash
curl -X POST https://your-auth0-domain.auth0.com/oauth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "your-m2m-client-id",
    "client_secret": "your-m2m-client-secret",
    "audience": "your-api-identifier",
    "grant_type": "client_credentials"
  }'
```

#### Test Endpoints
```bash
# Public endpoint
curl https://localhost:5001/api/test/public

# Protected endpoint
curl -H "Authorization: Bearer your-access-token" \
  https://localhost:5001/api/test/protected

# User claims endpoint
curl -H "Authorization: Bearer your-access-token" \
  https://localhost:5001/api/test/user

# Get current token
curl https://localhost:5001/api/auth/token
```

## PKCE Security Flow

This application implements the **PKCE (Proof Key for Code Exchange)** OAuth 2.0 flow for enhanced security:

1. **Client generates** a cryptographically random `code_verifier` (256 bits entropy)
2. **Client derives** `code_challenge` using SHA256 hash of the verifier
3. **Authorization request** includes the challenge (not the secret verifier)
4. **Auth0 redirects back** with authorization code
5. **Token exchange** includes the original verifier for validation
6. **Auth0 verifies** by comparing stored challenge with hashed verifier

This prevents authorization code interception attacks since attackers won't have the original verifier.

## Debugging & Development

### Browser Console Logs
- Open **Developer Tools (F12) > Console** to see detailed token flow logs
- Logs show: token detection, authorization flow, and token injection process

### Server Console Logs
- View real-time authentication process in the terminal
- Shows: token responses, token retrieval, and redirect URLs

### Configuration Classes
The project uses strongly-typed configuration with:
- `Auth0Settings` - Auth0 domain, client credentials, and audience
- `CorsSettings` - CORS policy configuration for cross-origin requests

## Project Structure

```
TestApp/
├── Program.cs                          # Main application with Auth0 + PKCE setup
├── TestApp.csproj                      # Project file with required packages
├── Configuration/
│   └── AppSettings.cs                  # Strongly-typed configuration classes
├── appsettings.json                    # Production configuration
├── appsettings.Development.json        # Development configuration
└── README.md                          # This documentation
```

## Dependencies

- **Microsoft.AspNetCore.Authentication.JwtBearer** (9.0.0) - JWT token validation
- **Microsoft.IdentityModel.Tokens** (9.0.0) - Token validation parameters
- **Swashbuckle.AspNetCore** (7.2.0) - Swagger/OpenAPI documentation
- **System.Text.Json** (9.0.0) - JSON serialization for token processing

## Security Features

- **PKCE Flow Implementation** - Prevents authorization code interception
- **Session-based State Management** - Secure OAuth state verification
- **CORS Configuration** - Controlled cross-origin access
- **JWT Token Validation** - Auth0 issuer and audience verification
- **Cryptographically Secure Random Generation** - For PKCE parameters

## UI Enhancements

- **Modern Button Design** - Gradient backgrounds with hover effects
- **Responsive Layout** - Clean, monochromatic design
- **Interactive Elements** - Smooth transitions and visual feedback
- **Clear Instructions** - Step-by-step guidance for all authentication methods
- **Real-time Token Display** - JSON-formatted token information
