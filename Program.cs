using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;
using TestApp.Configuration;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);
var corsSettings = builder.Configuration.GetSection("Cors").Get<CorsSettings>() ?? new CorsSettings();
var auth0Settings = builder.Configuration.GetSection("Auth0").Get<Auth0Settings>() ?? new Auth0Settings();

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

// Add session support for authentication flow
// Sessions are needed to securely store PKCE parameters (code_verifier, state) between
// the /auth/login redirect and the /auth/callback return from Auth0
// This prevents these sensitive values from being exposed in URLs or client-side storage
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);  // Session expires after 30 min of inactivity
    options.Cookie.HttpOnly = true;                  // Prevent XSS attacks on session cookie
    options.Cookie.IsEssential = true;               // Required for authentication flow to work
});

builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Auth0 Test API",
        Version = "v1",
        Description = "API for testing Auth0 authentication with JWT Bearer tokens"
    });

    // Add JWT Bearer authentication to Swagger
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Enter 'Bearer' [space] and then your token in the text input below.\r\n\r\nExample: \"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

// CORS configuration
builder.Services.AddCors(options =>
{
    options.AddPolicy(corsSettings.PolicyName, policy =>
    {
        if (corsSettings.AllowedOrigins.Contains("*"))
        {
            policy.AllowAnyOrigin();
        }
        else
        {
            policy.WithOrigins(corsSettings.AllowedOrigins);
        }

        if (corsSettings.AllowedMethods.Contains("*"))
        {
            policy.AllowAnyMethod();
        }
        else
        {
            policy.WithMethods(corsSettings.AllowedMethods);
        }

        if (corsSettings.AllowedHeaders.Contains("*"))
        {
            policy.AllowAnyHeader();
        }
        else
        {
            policy.WithHeaders(corsSettings.AllowedHeaders);
        }

        if (corsSettings.AllowCredentials)
        {
            policy.AllowCredentials();
        }
    });
});

// This sets up automatic JWT token validation for incoming requests
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
    {
        // Authority: Auth0's domain where the JWT issuer and signing keys are located
        // The middleware will automatically fetch the JWKS (JSON Web Key Set) from /.well-known/jwks.json
        options.Authority = $"https://{auth0Settings.Domain}/";

        // Audience: Validates that the JWT was intended for this API
        // Must match the "audience" claim in the token (configured in Auth0 API settings)
        options.Audience = auth0Settings.Audience;

        // Token validation parameters - these are the security checks performed on every request
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true, // Ensures token was issued by Auth0 (prevents token from other issuers)
            ValidateAudience = true, // Ensures token was intended for this API (prevents token reuse)
            ValidateLifetime = true, // Ensures token hasn't expired (checks 'exp' claim)
            ValidateIssuerSigningKey = true // Verifies token signature using Auth0's public keys
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(options =>
    {
        options.DocumentTitle = "Auth0 Test API";
        options.SwaggerEndpoint("/swagger/v1/swagger.json", "Auth0 Test API v1");
        options.EnablePersistAuthorization();
        options.DisplayRequestDuration();

        options.HeadContent = $@"
            <style>
                .auth0-login-section {{
                    background: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 8px;
                    padding: 24px;
                    margin: 20px 0;
                    text-align: center;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }}
                .auth0-login-btn {{
                    background: linear-gradient(135deg, #495057 0%, #343a40 100%);
                    color: #fff !important;
                    border: none;
                    padding: 12px 24px;
                    border-radius: 6px;
                    cursor: pointer;
                    text-decoration: none;
                    display: inline-block;
                    font-size: 14px;
                    font-weight: 500;
                    margin: 8px 4px;
                    transition: all 0.3s ease;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                    min-width: 140px;
                }}
                .auth0-login-btn:hover {{
                    background: linear-gradient(135deg, #6c757d 0%, #495057 100%);
                    transform: translateY(-1px);
                    box-shadow: 0 4px 8px rgba(0,0,0,0.25);
                }}
                .auth0-login-btn:active {{
                    transform: translateY(0);
                }}
                .auth0-login-btn.secondary {{
                    background: linear-gradient(135deg, #868e96 0%, #6c757d 100%);
                }}
                .auth0-login-btn.secondary:hover {{
                    background: linear-gradient(135deg, #adb5bd 0%, #868e96 100%);
                }}
                .token-info {{
                    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
                    border: 1px solid #ced4da;
                    border-radius: 8px;
                    padding: 18px;
                    margin: 18px 0;
                    font-size: 12px;
                    color: #495057;
                    text-align: left;
                    box-shadow: inset 0 1px 3px rgba(0,0,0,0.1);
                }}
                .token-info code {{
                    background: #e9ecef;
                    padding: 2px 6px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    font-size: 11px;
                }}
            </style>
            
            <script>
                window.addEventListener('load', function() {{
                    setTimeout(function() {{
                        const infoSection = document.querySelector('.information-container .info');
                        if (infoSection && !document.querySelector('.auth0-login-section')) {{
                            const authSection = document.createElement('div');
                            authSection.className = 'auth0-login-section';
                            authSection.innerHTML = `
                                <h3>Authentication</h3>
                                <p>Login with Auth0 to get your access token</p>
                                <a href='/auth/login' class='auth0-login-btn'>
                                    🔐 Login with Auth0
                                </a>
                                <div class='token-info'>
                                    <strong>How it works:</strong><br>
                                    1. Click 'Login with Auth0' to start PKCE authentication flow<br>
                                    2. Complete Auth0 login (redirects to auth0.com)<br>
                                    3. Return automatically with token set in Authorization<br>
                                    4. Test protected endpoints immediately<br><br>
                                    
                                    <strong>Debugging:</strong><br>
                                    Server console shows token exchange process in real-time
                                </div>
                            `;
                            infoSection.appendChild(authSection);
                        }}
                    }}, 1000);
                }});
                
                // Auto-set token from URL parameter
                window.addEventListener('load', function() {{
                    const urlParams = new URLSearchParams(window.location.search);
                    const token = urlParams.get('token');
                    console.log('Token from URL:', token ? token.substring(0, 20) + '...' : 'None');
                    
                    if (token) {{
                        console.log('Setting token automatically...');
                        setTimeout(function() {{
                            const authorizeBtn = document.querySelector('.authorize .btn');
                            if (authorizeBtn) {{
                                console.log('Clicking authorize button...');
                                authorizeBtn.click();
                                setTimeout(function() {{
                                    const tokenInput = document.querySelector('input[placeholder=""Value""]');
                                    if (tokenInput) {{
                                        tokenInput.value = 'Bearer ' + token;
                                        console.log('Token set in input field');
                                        const authorizeModalBtn = document.querySelector('.auth-btn-wrapper .btn-done');
                                        if (authorizeModalBtn) {{
                                            authorizeModalBtn.click();
                                            console.log('Authorization completed');
                                        }}
                                    }} else {{
                                        console.log('Token input field not found');
                                    }}
                                }}, 500);
                            }} else {{
                                console.log('Authorize button not found');
                            }}
                            window.history.replaceState({{}}, document.title, window.location.pathname);
                            alert('Token has been set! You can now test protected endpoints.');
                        }}, 1500);
                    }}
                }});
            </script>";
    });
}

// Authentication & Authorization Middleware Pipeline
// Order matters! These must be configured in the correct sequence for security to work properly

app.UseCors(corsSettings.PolicyName); // Handle CORS before authentication
app.UseSession(); // Enable session state for PKCE flow parameters

// Authentication middleware - validates JWT tokens and populates HttpContext.User
// This runs before authorization and extracts/validates the Bearer token from the Authorization header
app.UseAuthentication();

// Authorization middleware - enforces [Authorize] attributes based on the authenticated user
// This checks if the user (set by UseAuthentication) has permission to access protected endpoints
app.UseAuthorization();

// Auth0 PKCE Authentication Flow Endpoints
// PKCE (Proof Key for Code Exchange) is a security extension for OAuth 2.0 that prevents
// authorization code interception attacks, especially important for SPAs and native apps

// Step 1: Initiate Auth0 login using PKCE flow
app.MapGet("/auth/login", (HttpContext context) =>
{
    // Generate PKCE parameters for secure authorization code exchange
    var codeVerifier = GenerateCodeVerifier(); // Random string stored securely on client
    var codeChallenge = GenerateCodeChallenge(codeVerifier);  // SHA256 hash sent to Auth0
    var state = Guid.NewGuid().ToString("N")[..16]; // CSRF protection parameter
    var nonce = Guid.NewGuid().ToString("N")[..16]; // Replay attack protection (OIDC requirement)

    // Store PKCE parameters in session for validation during callback
    // These will be needed to exchange the authorization code for tokens
    context.Session.SetString("code_verifier", codeVerifier);
    context.Session.SetString("state", state);

    // Build Auth0 authorization URL with all required OIDC + PKCE parameters
    var authUrl = $"https://{auth0Settings.Domain}/authorize?" +
        $"response_type=code&" + // Request authorization code (not tokens directly)
        $"client_id={auth0Settings.ClientId}&" +
        $"redirect_uri={Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}/auth/callback")}&" +
        $"scope={Uri.EscapeDataString("openid profile email")}&" + // OIDC scopes for user info
        $"audience={Uri.EscapeDataString(auth0Settings.Audience)}&" + // API identifier for access token
        $"state={state}&" + // CSRF protection
        $"nonce={nonce}&" + // Replay protection
        $"code_challenge={codeChallenge}&" + // PKCE challenge (SHA256 of verifier)
        $"code_challenge_method=S256"; // PKCE method (SHA256)

    // Redirect user to Auth0 for authentication
    context.Response.Redirect(authUrl);
});

// Step 2: Handle Auth0 callback and exchange authorization code for tokens
app.MapGet("/auth/callback", async (HttpContext context) =>
{
    // Extract authorization response parameters from Auth0
    var code = context.Request.Query["code"].FirstOrDefault(); // Authorization code to exchange
    var state = context.Request.Query["state"].FirstOrDefault(); // State for CSRF validation
    var storedState = context.Session.GetString("state"); // Our original state value
    var codeVerifier = context.Session.GetString("code_verifier"); // PKCE code verifier

    // Security validations before proceeding with token exchange
    if (string.IsNullOrEmpty(code) || state != storedState || string.IsNullOrEmpty(codeVerifier))
    {
        // This prevents CSRF attacks and ensures the callback matches our login request
        return Results.BadRequest("Invalid authentication response");
    }

    // Exchange authorization code for access token using PKCE
    // This is a server-to-server call to Auth0's token endpoint
    using var httpClient = new HttpClient();
    var tokenRequest = new FormUrlEncodedContent(new[]
    {
        new KeyValuePair<string, string>("grant_type", "authorization_code"), // OAuth 2.0 grant type
        new KeyValuePair<string, string>("client_id", auth0Settings.ClientId),
        new KeyValuePair<string, string>("client_secret", auth0Settings.ClientSecret), // Client authentication
        new KeyValuePair<string, string>("code", code), // Authorization code from callback
        new KeyValuePair<string, string>("redirect_uri", $"{context.Request.Scheme}://{context.Request.Host}/auth/callback"),
        new KeyValuePair<string, string>("code_verifier", codeVerifier) // PKCE verifier proves we initiated the flow
    });

    var response = await httpClient.PostAsync($"https://{auth0Settings.Domain}/oauth/token", tokenRequest);

    if (response.IsSuccessStatusCode)
    {
        var tokenResponse = await response.Content.ReadAsStringAsync();
        Console.WriteLine($"Token Response: {tokenResponse}"); // Debug log

        // Parse token response (contains access_token, id_token, token_type, expires_in)
        var tokenData = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, object>>(tokenResponse);

        if (tokenData?.TryGetValue("access_token", out var accessToken) == true)
        {
            var tokenString = accessToken?.ToString() ?? "";
            Console.WriteLine($"Access Token Retrieved: {(tokenString.Length > 50 ? tokenString[..50] + "..." : tokenString)}"); // Debug log

            // Clean up session - remove temporary PKCE parameters (security best practice)
            context.Session.Remove("code_verifier");
            context.Session.Remove("state");

            // Redirect to Swagger UI with token as URL parameter for automatic authorization
            // The JavaScript in Swagger will automatically set this token in the Authorization header
            var swaggerUrl = $"/swagger?token={accessToken}";
            Console.WriteLine($"Redirecting to: {swaggerUrl}"); // Debug log
            return Results.Redirect(swaggerUrl);
        }
    }

    return Results.BadRequest("Failed to exchange code for token");
});

// API Endpoints demonstrating authentication behavior

// Public endpoint - accessible without authentication
// No [Authorize] attribute means the JWT Bearer middleware ignores this endpoint
app.MapGet("/api/test/public", () => new
{
    Message = "This is a public endpoint - no authentication required",
    Timestamp = DateTime.UtcNow
});

// Protected endpoint - requires valid JWT token
// [Authorize] attribute triggers JWT Bearer authentication middleware
// The middleware validates the token using the configuration set up above
app.MapGet("/api/test/protected", [Authorize] (HttpContext context) => new
{
    Message = "This is a protected endpoint - authentication required",
    User = context.User.Identity?.Name,  // User info extracted from validated JWT claims
    Timestamp = DateTime.UtcNow
    // Note: context.User.Claims contains all JWT claims (sub, aud, iss, exp, etc.)
    // context.User.Identity.IsAuthenticated will be true if JWT validation succeeded
});

app.MapControllers();

app.Run();

/// <summary>
/// Generates a cryptographically secure code verifier for PKCE (Proof Key for Code Exchange) flow.
/// 
/// PKCE Security Context:
/// PKCE is a security extension to OAuth 2.0 for public clients that helps prevent 
/// authorization code interception attacks. This is especially important for SPAs and 
/// native mobile apps that cannot securely store client secrets.
/// 
/// The code verifier is a cryptographically random string using the characters 
/// [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~", with a minimum length of 43 characters 
/// and a maximum length of 128 characters (RFC 7636).
/// 
/// Security Properties:
/// - High entropy (256 bits) makes it computationally infeasible to guess
/// - URL-safe encoding prevents issues during HTTP redirects
/// - One-time use prevents replay attacks
/// - Client-side generation means no network transmission of the verifier
/// 
/// Implementation Details:
/// 1. Generates 32 random bytes (256 bits of entropy) using cryptographic RNG
/// 2. Encodes as Base64 (results in 43+ characters, meeting RFC requirements)
/// 3. Makes it URL-safe by replacing '+' with '-' and '/' with '_' (RFC 4648 Section 5)
/// 4. Removes padding '=' characters as per RFC 7636 recommendations
/// </summary>
/// <returns>A URL-safe Base64-encoded string suitable for use as a PKCE code verifier</returns>
static string GenerateCodeVerifier()
{
    var bytes = new byte[32];
    using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();

    rng.GetBytes(bytes);

    return Convert.ToBase64String(bytes)
        .Replace("+", "-")
        .Replace("/", "_")
        .TrimEnd('=');
}

/// <summary>
/// Generates a code challenge from a code verifier for PKCE (Proof Key for Code Exchange) flow.
/// 
/// Security Purpose:
/// The code challenge is derived from the code verifier using SHA256 hashing and is sent 
/// to the authorization server during the initial authorization request. This allows the 
/// authorization server to verify that the client that exchanges the authorization code 
/// is the same client that initiated the request, without requiring the client to store 
/// or transmit the code verifier itself during the initial request.
/// 
/// PKCE Flow Security:
/// 1. Client generates random code_verifier (this method's input)
/// 2. Client derives code_challenge = SHA256(code_verifier) (this method's output)
/// 3. Client sends code_challenge to authorization server in /authorize request
/// 4. Authorization server stores code_challenge and returns authorization code
/// 5. Client exchanges authorization code + original code_verifier for tokens
/// 6. Authorization server verifies SHA256(received_code_verifier) == stored_code_challenge
/// 
/// This prevents authorization code interception attacks because an attacker would need
/// both the authorization code AND the original code verifier to get tokens.
/// 
/// Implementation Process:
/// 1. Takes the plain text code verifier as input
/// 2. Computes SHA256 hash of the verifier bytes (UTF-8 encoded)
/// 3. Encodes the hash as URL-safe Base64 (S256 method per RFC 7636)
/// 4. Returns the challenge to be sent with the authorization request
/// </summary>
/// <param name="codeVerifier">The code verifier string generated by GenerateCodeVerifier()</param>
/// <returns>A URL-safe Base64-encoded SHA256 hash of the code verifier</returns>
static string GenerateCodeChallenge(string codeVerifier)
{
    using var sha256 = System.Security.Cryptography.SHA256.Create();
    var challengeBytes = sha256.ComputeHash(System.Text.Encoding.UTF8.GetBytes(codeVerifier));

    return Convert.ToBase64String(challengeBytes)
        .Replace("+", "-")
        .Replace("/", "_")
        .TrimEnd('=');
}