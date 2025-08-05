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

## 📚 Learning Resources

### 🎯 **Essential Reading** (Start Here)

-   **[OAuth 2.0 Simplified](https://aaronparecki.com/oauth-2-simplified/)** - Best beginner-friendly OAuth 2.0 explanation
-   **[JWT Introduction](https://jwt.io/introduction)** - Understanding JSON Web Tokens with examples
-   **[Auth0 Getting Started](https://auth0.com/docs/get-started)** - Official Auth0 beginner guide

### 🔧 **Practical Tools** (For Development)

-   **[JWT.io Debugger](https://jwt.io/)** - Decode and inspect JWT tokens (paste your tokens here!)
-   **[Auth0 Management Dashboard](https://manage.auth0.com/)** - Configure your Auth0 applications
-   **[ASP.NET Core Authentication Docs](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/)** - Microsoft's official guide

### 🛡️ **Security Concepts** (Important to Understand)

-   **[PKCE Flow Explained](https://auth0.com/docs/get-started/authentication-and-authorization-flow/authorization-code-flow-with-proof-key-for-code-exchange-pkce)** - Why PKCE matters for security
-   **[OAuth 2.0 Security Best Practices](https://auth0.com/blog/oauth-2-best-practices-for-native-apps/)** - Common security pitfalls and how to avoid them

### 💡 **When You Get Stuck**

-   **[Auth0 Community](https://community.auth0.com/)** - Ask questions and get help from other developers
-   **[Stack Overflow - Auth0 Tag](https://stackoverflow.com/questions/tagged/auth0)** - Search existing solutions to common problems

### 🎥 **Video Learning** (If You Prefer Visual)

-   **[OAuth 2.0 and OpenID Connect](https://www.youtube.com/watch?v=996OiexHze0)** - 1-hour comprehensive explanation
-   **[PKCE Explained Visually](https://www.youtube.com/watch?v=CHzERullHe8)** - Short video on PKCE flow

## 🤝 Contributing

This is an educational example. Feel free to fork, modify, and use as a starting point for your own Auth0 integrations!

## 📄 License

MIT License - feel free to use this code in your projects.

---
