# 🔐 Auth0 ASP.NET Core Integration Example

A clean, well-documented ASP.NET Core Web API demonstrating secure Auth0 authentication using PKCE (Proof Key for Code Exchange) flow. This example shows how to implement OAuth 2.0 with JWT Bearer tokens in a modern .NET application.

## ✨ Features

-   **🔒 PKCE OAuth 2.0 Flow** - Secure authorization code exchange preventing interception attacks
-   **🎫 JWT Bearer Authentication** - Automatic token validation with Auth0's signing keys
-   **📚 Swagger Integration** - Interactive API documentation with built-in Auth0 login
-   **🛡️ Session-based Security** - Secure PKCE parameter storage during authentication flow
-   **🌐 Public & Protected Endpoints** - Examples of both authenticated and non-authenticated API routes
-   **📖 Comprehensive Documentation** - Well-commented code explaining security concepts

## 🚀 Quick Start

### 1. Prerequisites

-   .NET 9.0 SDK
-   Auth0 account (free tier available)

### 2. Auth0 Setup

1. Create a new **Application** in Auth0 Dashboard

    - Application Type: `Regular Web Application`
    - Note down: `Domain`, `Client ID`, `Client Secret`

2. Create a new **API** in Auth0 Dashboard

    - Note down: `API Identifier` (this will be your audience)

3. Configure Application Settings:
    - **Allowed Callback URLs**: `https://localhost:5001/auth/callback`
    - **Allowed Logout URLs**: `https://localhost:5001`
    - **Allowed Web Origins**: `https://localhost:5001`

### 3. Configuration

Update `appsettings.json` with your Auth0 settings:

```json
{
	"Auth0": {
		"Domain": "your-domain.auth0.com",
		"ClientId": "your-client-id",
		"ClientSecret": "your-client-secret",
		"Audience": "your-api-identifier"
	}
}
```

### 4. Run the Application

```bash
dotnet run
```

Navigate to: `https://localhost:5001/swagger`

### 5. Test Authentication

1. Click **"🔐 Login with Auth0"** button in Swagger UI
2. Complete Auth0 authentication
3. You'll be redirected back with automatic token setup
4. Test the protected endpoints immediately!

## 📋 API Endpoints

| Endpoint              | Method | Auth Required | Description                               |
| --------------------- | ------ | ------------- | ----------------------------------------- |
| `/api/test/public`    | GET    | ❌ No         | Public endpoint accessible to everyone    |
| `/api/test/protected` | GET    | ✅ Yes        | Protected endpoint requiring valid JWT    |
| `/auth/login`         | GET    | ❌ No         | Initiates Auth0 PKCE login flow           |
| `/auth/callback`      | GET    | ❌ No         | Handles Auth0 callback and token exchange |

## 🔧 How It Works

### Authentication Flow

1. **User clicks login** → Redirected to `/auth/login`
2. **PKCE parameters generated** → `code_verifier` and `code_challenge` created
3. **Redirect to Auth0** → User authenticates on Auth0's secure domain
4. **Auth0 callback** → User returns to `/auth/callback` with authorization code
5. **Token exchange** → Authorization code + PKCE verifier exchanged for JWT tokens
6. **Swagger integration** → Token automatically set in Swagger UI for testing

### Security Features

-   **PKCE Flow**: Prevents authorization code interception attacks
-   **State Parameter**: CSRF protection during OAuth flow
-   **JWT Validation**: Automatic signature, issuer, audience, and expiration validation
-   **Session Security**: HttpOnly cookies with secure PKCE parameter storage
-   **CORS Protection**: Configured for development with localhost origins

## 🏗️ Project Structure

```
├── Program.cs              # Main application with Auth0 integration
├── Configuration/
│   └── AppSettings.cs      # Configuration models for Auth0 and CORS
├── appsettings.json        # Application configuration
└── README.md              # This file
```

## 🔍 Key Code Components

### JWT Authentication Setup

```csharp
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = $"https://{auth0Settings.Domain}/";
        options.Audience = auth0Settings.Audience;
        // Automatic token validation with Auth0's public keys
    });
```

### Protected Endpoint Example

```csharp
app.MapGet("/api/test/protected", [Authorize] (HttpContext context) => new
{
    Message = "This is a protected endpoint",
    User = context.User.Identity?.Name,
    Timestamp = DateTime.UtcNow
});
```

## 🛠️ Development Notes

-   **HTTPS Required**: Auth0 requires HTTPS for security (configured for `localhost:5001`)
-   **Session Usage**: Only used for PKCE flow parameters, not for token storage
-   **Token Storage**: Tokens are managed client-side in Swagger UI for testing
-   **Error Handling**: Basic error responses for invalid authentication attempts

## 📚 Learning Resources

-   [Auth0 Documentation](https://auth0.com/docs)
-   [PKCE RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)
-   [JWT Introduction](https://jwt.io/introduction)
-   [ASP.NET Core Authentication](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/)

## 🤝 Contributing

This is an educational example. Feel free to fork, modify, and use as a starting point for your own Auth0 integrations!

## 📄 License

MIT License - feel free to use this code in your projects.

---

**Perfect for developers learning Auth0 integration or as a starting point for secure API development.**

### Configuration Classes

The project uses strongly-typed configuration with:

-   `Auth0Settings` - Auth0 domain, client credentials, and audience
-   `CorsSettings` - CORS policy configuration for cross-origin requests

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

-   **Microsoft.AspNetCore.Authentication.JwtBearer** (9.0.0) - JWT token validation
-   **Microsoft.IdentityModel.Tokens** (9.0.0) - Token validation parameters
-   **Swashbuckle.AspNetCore** (7.2.0) - Swagger/OpenAPI documentation
-   **System.Text.Json** (9.0.0) - JSON serialization for token processing

## Security Features

-   **PKCE Flow Implementation** - Prevents authorization code interception
-   **Session-based State Management** - Secure OAuth state verification
-   **CORS Configuration** - Controlled cross-origin access
-   **JWT Token Validation** - Auth0 issuer and audience verification
-   **Cryptographically Secure Random Generation** - For PKCE parameters

## UI Enhancements

-   **Modern Button Design** - Gradient backgrounds with hover effects
-   **Responsive Layout** - Clean, monochromatic design
-   **Interactive Elements** - Smooth transitions and visual feedback
-   **Clear Instructions** - Step-by-step guidance for all authentication methods
-   **Real-time Token Display** - JSON-formatted token information
