# Ktor OAuth / OpenID Authorization Server

A **Kotlin + Ktor** implementation of a self-hosted OAuth 2.0 Authorization Server with OpenID Connect (OIDC) support.  
This library provides core features you'd expect from an OAuth / OIDC server: clients, tokens, consent, JWT issuance.

---

## 🚀 Features

- OAuth 2.0 **Authorization Code** flow
- OAuth 2.0 **Client Credentials** flow
- **Refresh Token** issuance and rotation
- OpenID Connect (OIDC) **ID Token** as signed JWT
- JWT-signed **Access Tokens**
- `/userinfo`, `/introspect`, `/revoke` endpoints
- OIDC Discovery: `/.well-known/openid-configuration`
- JWKS endpoint: `/.well-known/jwks.json`
- Login page with customization options
- Consent screen + persistent consent storage
- Secure encrypted & signed Ktor cookie sessions
- Client storage via PostgreSQL/Exposed or in-memory
- RSA key loading from PEM or auto-generation
- Custom JWT claim injection

---

## Table of contents

- [🚀 Features](#-features)
- [Getting started](#getting-started)
    - [Dependencies](#dependencies-gradle)
    - [Configuration](#configuration)
    - [Default User Credentials Created](#default-user-credentials-created)
    - [Default Client Credentials Created](#default-client-credentials-created)
    - [Database](#database)
- [Endpoints](#endpoints)
- [Database schema migrations](#database-schema-migrations)
- [Sessions & security](#sessions--security)
    - [JWKS Certificate configuration](#jwks-certificate-configuration)
- [Token design and claims](#token-design-and-claims)
    - [Scopes & `/userinfo`](#scopes--userinfo)
- [Login and Consent UI templates (Mustache)](#login-and-consent-ui-templates-mustache)
- [Examples](#examples)
    - [Authorization Code (high-level)](#authorization-code-high-level)
    - [Client Credentials](#client-credentials)
- [Dependency Providers](#-dependency-providers)
    - [Database-Level Providers](#-database-level-providers)
    - [OAuth Core Service Providers](#-oauth-core-service-providers)
    - [JWT Providers](#-jwt-providers)
    - [Customization Providers](#-customization-providers)
    - [Your own providers](#your-own-providers)
    - [Putting It All Together (Using Default Database Providers)](#-putting-it-all-together-using-default-database-providers)
    - [Oauth2 Client configuration](#oauth2-client-configuration)
    - [Endpoint Config](#endpoint-config)
    - [Example secured api endpoint](#example-secured-api-endpoint)
    - [Example Database Providers](#-example-database-providers)
    - [Example InMemory Providers](#-example-inmemory-providers)
    - [Example Ktor IDP server with Multi Tenancy and 2fa implementation](#-example-ktor-idp-server-with-multi-tenancy-and-2fa-implementation)
- [Testing](#testing)
- [Operational notes & best practices](#operational-notes--best-practices)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- OAuth 2.0: `authorization_code` (with PKCE), `refresh_token`, `client_credentials`
- OpenID Connect: `id_token` as a signed JWT; discovery (`/.well-known/openid-configuration`) and JWKS (`/.well-known/jwks.json`)
- Both **access tokens** and **ID tokens** are signed JWTs (RS256)
- Token rotation for refresh tokens
- Consent pages (mustache templates) and persistent consent storage
- Ktor routes for login, authorize, token, revoke, introspect, userinfo
- Exposed + PostgreSQL schema with example migrations (Flyway shown)
- In-memory service providers for easier testing
- Flexible configuration and hooks for customizing claims

---

## Getting started

### Dependencies (Gradle)

Add in `build.gradle.kts`:

```kotlin
// =========================
// 🚀 Ktor Server & Client
// =========================
implementation("io.ktor:ktor-server-core:<ktor_version>")
implementation("io.ktor:ktor-server-netty:<ktor_version>")
implementation("io.ktor:ktor-server-content-negotiation:<ktor_version>")
implementation("io.ktor:ktor-serialization-kotlinx-json:<ktor_version>")
implementation("io.ktor:ktor-serialization-gson:<ktor_version>")
implementation("io.ktor:ktor-server-auth:<ktor_version>")
implementation("io.ktor:ktor-server-auth-jwt:<ktor_version>")
implementation("io.ktor:ktor-server-mustache:<ktor_version>")
implementation("io.ktor:ktor-server-config-yaml:<ktor_version>")
implementation("io.ktor:ktor-server-di:<ktor_version>")

// Ktor Client
implementation("io.ktor:ktor-client-core:<ktor_version>")
implementation("io.ktor:ktor-client-apache:<ktor_version>")

// Logging
implementation("ch.qos.logback:logback-classic:<logback_version>")

// =========================
// 🗄️ Database & Migrations
// =========================
implementation("org.jetbrains.exposed:exposed-core:<exposed_version>")
implementation("org.jetbrains.exposed:exposed-jdbc:<exposed_version>")
implementation("org.jetbrains.exposed:exposed-java-time:0.61.0")

implementation("org.postgresql:postgresql:<postgres_version>")
implementation("com.zaxxer:HikariCP:4.0.3")
implementation("org.flywaydb:flyway-core:9.22.3")

// =========================
// 🔐 Security & Utilities
// =========================
implementation("at.favre.lib:bcrypt:0.10.2")
implementation("com.nimbusds:nimbus-jose-jwt:10.6")

// =========================
// ⭐ OAuth / OpenID Server Library
// =========================
implementation("com.bittokazi.sonartype:ktor-oauth-authorization-server:1.0.4")
```

Replace `<...>` with concrete versions used in your project.

---

### Configuration

Provide configuration (e.g. `application.yaml` or environment variables) for:

- Database JDBC URL, user, password
- Session keys (encryption & signing) — **must be persistent** across restarts
- RSA private/public key paths for signing (`private_key.pem`, `public_key.pem`)
- Token lifetimes (access, refresh, code expiry)
- Application `issuer` (e.g. `https://auth.example.com`)

Example environment variables:

```yaml
ktor:
  application:
    modules:
      - com.bittokazi.example.ktor.ApplicationKt.module
  deployment:
    port: 8080

database:
  url: ${DB_URL}
  driver: "org.postgresql.Driver"
  schema: "public"
  username: ${DB_USERNAME}
  password: ${DB_PASSWORD}

jwk:
  key-id: "my-key-id"

oauth:
  session:
    timeout: 3600
```

### Default User Credentials Created

| username                  | password                                        |
|---------------------------|-------------------------------------------------|
| **admin**                 | **password**                                    |

### Default Client Credentials Created

| Client Id          | Client Secret |
|--------------------|---------------|
| **default-client** | **password**  |

---

### Database

This project uses Exposed with PostgreSQL. Migrations can be performed with Flyway. Migration files are included in `oauth_db` for Flyway convention.
The below tables will be created by default
- oauth_clients
- oauth_users
- oauth_refresh_tokens
- oauth_access_tokens
- oauth_authorization_codes
- oauth_consents
---

## Endpoints

The below endpoints are created by the library

- `GET /oauth/authorize` — authorization endpoint (interactive). Checks session; if no session, saves request and redirects to `/oauth/login`.
- `GET, POST /oauth/login` — login page and submit handler (sets secure session).
- `POST /oauth/token` — token endpoint (authorization_code, refresh_token, client_credentials).
- `POST /oauth/revoke` — token revocation (accepts access or refresh token).
- `POST /oauth/introspect` — token introspection.
- `GET /oauth/userinfo` — OIDC userinfo endpoint (requires access token).
- `GET /.well-known/openid-configuration` — discovery document.
- `GET /.well-known/jwks.json` — public JWKS for verifying tokens.

---

## Database schema migrations

Typical tables:

- `oauth_users` — users
- `oauth_clients` — clients (client_id, client_secret_hash, redirect_uris, scopes, grant_types, is_default, ...)
- `oauth_authorization_codes` — authorization codes (code, client_id, user_id, redirect_uri, scopes, code_challenge, expires_at, consumed)
- `oauth_access_tokens` — issued access tokens (id, token, client_id, user_id, scopes, issued_at, expires_at, revoked, refresh_token_id?)
- `oauth_refresh_tokens` — refresh tokens (id, token, client_id, user_id, scopes, expires_at, revoked, rotated_to)
- `oauth_consents` — user consents per client (id, user_id, client_id, scopes)

### Enforce single default client

To allow exactly one `is_default = true` client and prevent change/delete:

---

## Sessions & security

**Do not** trust a cookie that contains only `userId`. Use signed and encrypted cookies or server-side sessions.

Ktor example (persistent keys loaded from env):

```yaml
oauth:
  session:
    timeout: 3600
    encryption-key: dd78055a2c57f50a636efe0e034764f7 # has to be 32 character. set your own. uncomment to set otherwise will be generated on application restart
    signing-key: a94f3c2e8b7f5d4c1e0296a1b3d8f7e2 # has to be 32 character. set your own. uncomment to set otherwise will be generated on application restart
```

---


### JWKS Certificate configuration

```yaml
jwk:
  key-id: "my-key-id"
  private-key-path: certificates/default_private_key_pkcs8.pem # provide your own certificate otherwise will be generated on everytime on app start
  public-key-path: certificates/default_public_key.pem # provide your own certificate otherwise will be generated on everytime on app start
```

---

## Token design and claims

- **ID Token** (OIDC): required claims: `iss`, `sub`, `aud`, `exp`, `iat`. Optional: `nonce`, `auth_time`, `acr`, `amr`, profile/email claims depending on scopes.
- **Access Token**: include `iss`, `sub`, `aud`, `scope`, `exp`, `iat`, optional `jti`.
- **token_type** (e.g. `"Bearer"`) is part of the token response JSON — not a built-in JWT claim. If you want, add custom claim `"token_type": "access_token"`.

### Scopes & `/userinfo`

- To call `/userinfo`, the access token **must include** the `openid` scope. Additional claims require `profile`, `email`, etc.
- `/userinfo` should be called with the **access token** (Authorization: Bearer <token>).

---

## Login and Consent UI templates (Mustache)

Example `consent.hbs` (already included in templates `oauth2_templates` under `resouces`):

```html
<!-- consent.hbs -->
<!DOCTYPE html>
<html>
<head> ... styles ... </head>
<body>
<h2>Authorize {{clientName}}</h2>
<ul>
    {{#scopes}}<li>{{.}}</li>{{/scopes}}
</ul>
<form method="POST" action="/oauth/consent">
    <input type="hidden" name="client_id" value="{{clientId}}">
    <input type="hidden" name="redirect" value="{{redirect}}">
    <button name="action" value="approve">Approve</button>
    <button name="action" value="deny">Deny</button>
</form>
</body>
</html>
```

Example `login.hbs` (already included in templates `oauth2_templates` under `resouces`):

```html
<!-- login.hbs -->
<!DOCTYPE html>
<html>
<head> ... styles ... </head>
<body>
<div class="login-container">
    <h2>Login</h2>

    {{#error}}
    <div class="error">{{errorMessage}}</div>
    {{/error}}

    <form method="POST" action="/oauth/login">
        <input type="hidden" name="redirect" value="{{redirect}}" />

        <input type="text" name="username" placeholder="Username" required autofocus>
        <input type="password" name="password" placeholder="Password" required>

        <div class="remember-me">
            <input type="checkbox" id="remember" name="rememberMe" value="true">
            <label for="remember">Remember me</label>
        </div>

        <button type="submit">Login</button>
    </form>
</div>
</body>
</html>
```

Also included `consent_denied.hbs` seen in the repo.

If you want to use yours just create a folder `oauth2_templates` under `resouces`
and create files `login.hbs`, `consent.hbs`, `consent_denied.hbs` as needed.

Reference here: https://github.com/bittokazi/ktor-oauth-authorization-server/tree/main/src/main/resources/oauth2_templates

---

## Examples

### Authorization Code (high-level)

1. Client redirects user:  
   `GET /oauth/authorize?response_type=code&client_id=...&redirect_uri=...&scope=openid+profile+email&state=...&code_challenge=...`
2. Server checks session; redirects to login if needed.
3. User logs in; server issues code and redirects back: `redirect_uri?code=...&state=...`
4. Client exchanges code at `/oauth/token` (POST) with `grant_type=authorization_code`.
5. Server verifies code, issues `access_token`, `id_token` (both JWT), and `refresh_token`.

### Client Credentials

- Client posts to `/oauth/token` with `grant_type=client_credentials` and client authentication.
- Server issues JWT access token with `sub` set to client id and `aud` matching the API.

---

## ⚙️ Dependency Providers

To run the OAuth server, you must configure the following providers in your dependency container.  
Below is a **list** with explanations of what each provider does.

---

## 📁 Database-Level Providers

These providers configure the database-backed implementations for storing users, clients, and OAuth data.

| Provider | Implementation | Description |
|---------|----------------|-------------|
| `OauthDatabaseConfiguration` | `DefaultOauthDatabaseConfiguration` | Holds database configuration for OAuth-related tables. |
| `OauthUserServiceDatabaseProvider` | `OauthUserServiceDatabaseProvider` | Database implementation for user lookup, authentication, and creation. |
| `OauthClientServiceDatabaseProvider` | `OauthClientServiceDatabaseProvider` | Database-backed provider for OAuth client registration & lookup. |

```kotlin
dependencies {
    provide<OauthDatabaseConfiguration>(DefaultOauthDatabaseConfiguration::class)
    provide<OauthUserServiceDatabaseProvider>(OauthUserServiceDatabaseProvider::class)
    provide<OauthClientServiceDatabaseProvider>(OauthClientServiceDatabaseProvider::class)
}

val oauthUserServiceDatabaseProvider: OauthUserServiceDatabaseProvider by dependencies
val oauthClientServiceDatabaseProvider: OauthClientServiceDatabaseProvider by dependencies
```

---

## 🔐 OAuth Core Service Providers

These are the core services required for OAuth 2.0 flows.

| Provider | Implementation | Purpose |
|----------|----------------|---------|
| `OauthUserService` | Provided by `OauthUserServiceDatabaseProvider` | Handles user authentication and user information queries. |
| `OauthClientService` | Provided by `OauthClientServiceDatabaseProvider` | Manages OAuth clients (apps requesting tokens). |
| `OauthAuthorizationCodeService` | `OauthAuthorizationCodeServiceDatabaseProvider` | Stores & retrieves authorization codes for Authorization Code Flow. |
| `OauthTokenService` | `OauthTokenServiceDatabaseProvider` | Generates, persists, and retrieves access & refresh tokens. |
| `OauthConsentService` | `OauthConsentServiceDatabaseProvider` | Manages user consent for scopes. |

```kotlin
dependencies {
    provide<OauthUserService> { oauthUserServiceDatabaseProvider }
    provide<OauthClientService> { oauthClientServiceDatabaseProvider }
    provide<OauthAuthorizationCodeService>(OauthAuthorizationCodeServiceDatabaseProvider::class)
    provide<OauthTokenService>(OauthTokenServiceDatabaseProvider::class)
    provide<OauthConsentService>(OauthConsentServiceDatabaseProvider::class)
}
```

---

## 🔑 JWT Providers

These providers manage signing keys, token customization, and JWT verification.

| Provider | Implementation | Purpose |
|----------|----------------|---------|
| `JwtTokenCustomizer` | `JwtCustomizerImpl` | Allows adding custom claims before tokens are issued. |
| `JwksProvider` | `JwksProvider` | Exposes JWKS for public key discovery by clients. |
| `JwtVerifier` | `JwtVerifier` | Verifies signed JWT access tokens. |

```kotlin
dependencies {
    provide<JwtTokenCustomizer>(JwtCustomizerImpl::class)
    provide(JwksProvider::class)
    provide(JwtVerifier::class)
}
```

---

## 🎛️ Customization Providers

These allow integration with your session and application login/logout flow.

| Provider | Implementation | Purpose |
|----------|----------------|---------|
| `SessionCustomizer` | `SessionCustomizer` | Customize session behavior (storage, cookies, etc.). |
| `OauthLoginOptionService` | `DefaultOauthLoginOptionService("/home")` | Controls the redirect location after login. |
| `OauthLogoutActionService` | `DefaultOauthLogoutActionService("/home")` | Controls the redirect location after logout. |

```kotlin
dependencies {
    provide(SessionCustomizer::class)

    provide<OauthLoginOptionService> {
        DefaultOauthLoginOptionService("/home")
    }

    provide<OauthLogoutActionService> {
        DefaultOauthLogoutActionService("/home")
    }
}
```

---

# Your own providers

You can implement any provider and customize as you want.

Example implementation of  `OauthUserService` provider to use your own user table

```kotlin
class UserService(
    val oauthDatabaseConfiguration: OauthDatabaseConfiguration
): OauthUserService {

    override fun findByUsername(
        username: String,
        call: ApplicationCall
    ): OAuthUserDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        Users.selectAll()
            .where { Users.email eq username }
            .map {
                OAuthUserDTO(
                    id = it[Users.id].toString(),
                    username = it[Users.email],
                    email = it[Users.email],
                    firstName = it[Users.firstName],
                    lastName = it[Users.lastName],
                    isActive = true,
                    passwordHash = it[Users.hashedPassword]
                )
            }.singleOrNull()
    }

    override fun findById(
        id: String,
        call: ApplicationCall
    ): OAuthUserDTO? = oauthDatabaseConfiguration.dbQuery(call) {
        Users.selectAll()
            .where { Users.id eq id.toLong() }
            .map {
                OAuthUserDTO(
                    id = it[Users.id].toString(),
                    username = it[Users.email],
                    email = it[Users.email],
                    firstName = it[Users.firstName],
                    lastName = it[Users.lastName],
                    isActive = true,
                    passwordHash = it[Users.hashedPassword]
                )
            }.singleOrNull()
    }
}
```

---

## 🧩 Putting It All Together (Using Default Database Providers)

Your full provider configuration looks like this:

https://github.com/bittokazi/ktor-oauth-authorization-server/blob/main/examples/ktor-oauth-server-databse-imlementation/src/main/kotlin/Application.kt

```kotlin
package com.bittokazi.example.ktor

import com.bittokazi.ktor.auth.configureOauth2AuthorizationServer
import com.bittokazi.ktor.auth.database.DefaultOauthDatabaseConfiguration
import com.bittokazi.ktor.auth.database.OauthDatabaseConfiguration
import com.bittokazi.ktor.auth.services.JwksProvider
import com.bittokazi.ktor.auth.services.JwtTokenCustomizer
import com.bittokazi.ktor.auth.services.JwtVerifier
import com.bittokazi.ktor.auth.services.SessionCustomizer
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.DefaultOauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OAuthClientDTO
import com.bittokazi.ktor.auth.services.providers.OauthAuthorizationCodeService
import com.bittokazi.ktor.auth.services.providers.OauthClientService
import com.bittokazi.ktor.auth.services.providers.OauthConsentService
import com.bittokazi.ktor.auth.services.providers.OauthLoginOptionService
import com.bittokazi.ktor.auth.services.providers.OauthLogoutActionService
import com.bittokazi.ktor.auth.services.providers.OauthTokenService
import com.bittokazi.ktor.auth.services.providers.OauthUserService
import com.bittokazi.ktor.auth.services.providers.database.OauthAuthorizationCodeServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthClientServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthConsentServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthTokenServiceDatabaseProvider
import com.bittokazi.ktor.auth.services.providers.database.OauthUserServiceDatabaseProvider
import io.ktor.server.application.*
import io.ktor.server.plugins.di.dependencies

fun main(args: Array<String>) {
    io.ktor.server.netty.EngineMain.main(args)
}

fun Application.module() {
    configureSecurity()

    dependencies {
        provide<OauthDatabaseConfiguration>(DefaultOauthDatabaseConfiguration::class)
        provide<OauthUserServiceDatabaseProvider>(OauthUserServiceDatabaseProvider::class)
        provide<OauthClientServiceDatabaseProvider>(OauthClientServiceDatabaseProvider::class)
    }

    val oauthUserServiceDatabaseProvider: OauthUserServiceDatabaseProvider by dependencies
    val oauthClientServiceDatabaseProvider: OauthClientServiceDatabaseProvider by dependencies

    dependencies {
        provide<OauthUserService> { oauthUserServiceDatabaseProvider }
        provide<OauthClientService> { oauthClientServiceDatabaseProvider }
        provide<OauthAuthorizationCodeService>(OauthAuthorizationCodeServiceDatabaseProvider::class)
        provide<OauthTokenService>(OauthTokenServiceDatabaseProvider::class)
        provide<OauthConsentService>(OauthConsentServiceDatabaseProvider::class)
        provide<JwtTokenCustomizer>(JwtCustomizerImpl::class)
        provide(JwksProvider::class)
        provide(JwtVerifier::class)
        provide(SessionCustomizer::class)
        provide<OauthLoginOptionService> {
            DefaultOauthLoginOptionService("/home")
        }
        provide<OauthLogoutActionService> {
            DefaultOauthLogoutActionService("/home")
        }
    }

    configureOauth2AuthorizationServer(
        configureSerialization = true,
        defaultLoginRoutes = true,
        defaultAuthorizeRoute = true,
        defaultOidcRoute = true,
        defaultTokenRoute = true,
        defaultConsentRoute = true
    )

    configureRouting()
}

class JwtCustomizerImpl: JwtTokenCustomizer {
    override fun customize(
        user: String?,
        client: OAuthClientDTO?
    ): Map<String, String> {
        return mapOf("extra-scope" to "test-value")
    }
}
```


### Oauth2 Client configuration

```kotlin
fun Application.configureSecurity() {
    authentication {
        oauth("ktor-oauth2") {
            urlProvider = { "http://localhost:8080/auth/callback" }
            providerLookup = {
                OAuthServerSettings.OAuth2ServerSettings(
                    name = "ktor-auth-server",
                    authorizeUrl = "http://localhost:8080/oauth/authorize",
                    accessTokenUrl = "http://localhost:8080/oauth/token",
                    requestMethod = HttpMethod.Post,
                    clientId = "default-client",
                    clientSecret = "password",
                    defaultScopes = listOf("openid profile email")
                )
            }
            client = HttpClient(Apache)
        }

        oauthAuthenticationConfig("http://localhost:8080")
    }
}
```

### Endpoint Config

```kotlin
fun Application.configureRouting() {

    val oauthLoginOptionService: OauthLoginOptionService by dependencies

    routing {
        authenticate("ktor-oauth2") {
            get("/login") {
                // Redirects to 'authorizeUrl' automatically
            }

            get("/auth/callback") {
                val currentPrincipal: OAuthAccessTokenResponse.OAuth2? = call.principal()
                // redirects home if the url is not found before authorization
                currentPrincipal?.let { principal ->
                    principal.state?.let { state ->
                        //call.sessions.set(UserSession(state, principal.accessToken))
                        return@get call.respond(currentPrincipal)
                    }
                }
                call.respondRedirect("/home")
            }
        }
    }

    userRoutes()
    clientRoutes()
}
```

### Example secured api endpoint

```kotlin
fun Application.userRoutes() {
    val oauthUserServiceDatabaseProvider: OauthUserServiceDatabaseProvider by dependencies

    routing {
        authenticate {
            get("/api/users/whoami") {
                call.principal<JWTPrincipal>()?.let { principal ->
                    call.respond(
                        oauthUserServiceDatabaseProvider
                            .findById(principal.subject!!, call).also { it?.passwordHash = "" } as Any
                    )
                }
            }

            get("/api/users") {
                call.respond(
                    oauthUserServiceDatabaseProvider.runQuery(call) { users ->
                        users.selectAll().map {
                            OAuthUserDTO(
                                it[OAuthUsers.id],
                                it[OAuthUsers.username],
                                it[OAuthUsers.email],
                                it[OAuthUsers.firstName],
                                it[OAuthUsers.lastName],
                                it[OAuthUsers.isActive]
                            )
                        }
                    }
                )
            }
        }
    }
}
```

---

## 🧩 Example Database Providers

https://github.com/bittokazi/ktor-oauth-authorization-server/tree/main/examples/ktor-oauth-server-databse-imlementation

---

## 🧩 Example InMemory Providers

https://github.com/bittokazi/ktor-oauth-authorization-server/tree/main/examples/ktor-oauth-server-inmemory-imlementation

---

## 🧩 Example Ktor IDP server with Multi Tenancy and 2fa implementation

https://github.com/bittokazi/ktor-oauth-authorization-server/tree/main/examples/ktor-oauth-server-mutit-tenant-with-two-fa-imlementation

---

## Testing

- Use `Default InMemory Providers` implementations for testing.

---

## Contributing

1. Fork the repo
2. Create a feature branch
3. Add documentation
4. Open a PR

Please follow repository coding style and include migration/versioning updates for DB changes.

---

## License

Add your chosen license (MIT / Apache 2.0 / etc).

---
