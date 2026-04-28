# EUDI PID Wallet Login Demo

One deployable Spring Boot app for a demo EU Digital Identity Wallet PID login flow.

The app now plays both backend roles:

- QR/request generator
- verifier/relying-party demo app that receives wallet `direct_post` responses

The only separate app is the mobile wallet app built by a colleague.

## What It Does

- Runs on Java 21, Spring Boot 3.x, Maven, Thymeleaf, and Spring Security.
- Supports dummy username/password login for demo setup access.
- Generates demo root CA and verifier/client certificate material.
- Exposes certificate downloads and JWKS.
- Creates OID4VP-style PID login sessions.
- Generates QR codes pointing to public request-object URLs served by this same app.
- Signs request objects as JWT/JAR-style request objects.
- Accepts wallet `direct_post` responses at `/oid4vp/direct_post`.
- Performs simplified PID presentation verification and creates a PID-authenticated web session.

## What It Does Not Do

- It is not production EUDI Wallet compliance software.
- It does not implement complete SD-JWT VC cryptographic validation.
- It does not persist login sessions across restarts.
- It does not provide production-grade certificate or private-key management.

The certificate material is demo-only.

## Local Run

```bash
mvn -s .mvn/settings.xml spring-boot:run
```

Open:

```text
http://localhost:8080
```

Dummy login:

```text
demo / demo
```

For local wallet testing, expose the app publicly using a tunnel or deploy to Railway. A mobile wallet cannot fetch request objects from `localhost` on your laptop.

## Railway Deploy

Railway should detect the Maven Spring Boot app. The app respects Railway's `PORT` env var:

```properties
server.port=${PORT:${SERVER_PORT:8080}}
```

Set this required Railway variable:

```text
APP_PUBLIC_BASE_URL=https://your-app.up.railway.app
```

Recommended optional variables:

```text
APP_CLIENT_ID=demo-eudi-pid-verifier
APP_CLIENT_ID_SCHEME=x509_san_dns
APP_QR_URI_MODE=openid4vp
APP_INCLUDE_NATIONALITY=true
APP_REQUEST_TTL_SECONDS=300
APP_CERTIFICATE_OUTPUT_DIR=certs
APP_ROOT_CA_PEM=
APP_ROOT_CA_KEY_PEM=
APP_CLIENT_CERT_PEM=
APP_CLIENT_KEY_PEM=
```

The generated QR and request object use `APP_PUBLIC_BASE_URL`, for example:

```text
openid4vp://authorize?client_id=demo-eudi-pid-verifier&client_id_scheme=x509_san_dns&request_uri=https://your-app.up.railway.app/oid4vp/requests/{id}/object.jwt
```

## Certificate Handling

Local dev writes demo certificate files under:

```text
certs/
```

Generated files:

- `certs/demo-root-ca.pem`
- `certs/demo-root-ca-key.pem`
- `certs/demo-client-cert.pem`
- `certs/demo-client-key.pem`

Railway filesystem persistence should not be assumed. By default, the app regenerates demo material on startup. To keep stable demo trust across redeploys, set all four PEM environment variables:

- `APP_ROOT_CA_PEM`
- `APP_ROOT_CA_KEY_PEM`
- `APP_CLIENT_CERT_PEM`
- `APP_CLIENT_KEY_PEM`

PEM values may include literal newline characters or escaped `\n` sequences.

Certificate endpoints:

- `GET /certs/root-ca.pem`
- `GET /certs/client-cert.pem`
- `GET /certs/jwks.json`

## Pages

- `/login`: dummy login.
- `/`: dashboard.
- `/certificates`: setup page for demo certificates.
- `/wallet-login`: start a mobile wallet login.
- `/wallet-login/{id}`: QR, state, nonce, request URI, request object, and status polling.
- `/profile`: dummy user profile or verified PID claims.

## OID4VP Endpoints

- `POST /oid4vp/sessions`: create a wallet-login session.
- `GET /oid4vp/sessions/{id}`: session JSON.
- `GET /oid4vp/sessions/{id}/qr`: QR PNG.
- `GET /oid4vp/sessions/{id}/status`: polling endpoint; authenticates browser session when verified.
- `GET /oid4vp/requests/{id}/object.jwt`: signed request object.
- `GET /oid4vp/requests/{id}/payload.json`: unsigned payload for debugging.
- `POST /oid4vp/direct_post`: wallet response endpoint.

## Wallet Response

Expected `direct_post` body:

```json
{
  "state": "generated-state",
  "vp_token": "{...or compact JWT...}",
  "presentation_submission": {
    "id": "presentation-submission-id",
    "definition_id": "pid-identification",
    "descriptor_map": []
  }
}
```

The simplified verifier checks:

- `state` exists and maps to a pending session.
- request has not expired.
- `nonce` matches if a nonce is present in the parsed `vp_token`.
- required PID claims exist.

Required PID claims:

- `given_name`
- `family_name`
- `birth_date`
- `person_identifier`
- `nationality` when requested

The verification code is intentionally isolated in `PresentationVerificationService` so a real SD-JWT VC / OID4VP verifier can replace it later.
