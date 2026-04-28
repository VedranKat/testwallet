# Mobile App Integration

This document describes how the separate mobile wallet app should integrate with the deployed Spring Boot verifier demo.

## QR URI Format

Default QR mode is `openid4vp`.

```text
openid4vp://authorize?client_id={client_id}&client_id_scheme=x509_san_dns&request_uri={APP_PUBLIC_BASE_URL}/oid4vp/requests/{id}/object.jwt
```

Example:

```text
openid4vp://authorize?client_id=demo-eudi-pid-verifier&client_id_scheme=x509_san_dns&request_uri=https://your-app.up.railway.app/oid4vp/requests/{id}/object.jwt
```

The wallet should fetch `request_uri` over public HTTPS. Do not use localhost for mobile integration.

## Request Object URL

```text
GET {APP_PUBLIC_BASE_URL}/oid4vp/requests/{id}/object.jwt
```

The response is a compact signed JWT with:

- `typ=oauth-authz-req+jwt`
- `alg=RS256`
- `kid={client_id}`
- `x5c` containing the demo verifier/client certificate

## Signed Request Object Fields

The JWT payload contains:

- `iss`
- `aud`
- `iat`
- `exp`
- `jti`
- `client_id`
- `client_id_scheme`
- `response_type=vp_token`
- `response_mode=direct_post`
- `response_uri={APP_PUBLIC_BASE_URL}/oid4vp/direct_post`
- `state`
- `nonce`
- `presentation_definition`

## Presentation Definition

The request uses Presentation Exchange-style naming:

- `id=pid-identification`
- input descriptor `id=eu-pid`
- format `vc+sd-jwt`
- purpose `PID-based identification for login`

Requested claims:

- `given_name`
- `family_name`
- `birth_date`
- `person_identifier`
- `nationality` when enabled

## Direct Post Endpoint

Wallet responses go back to the same Spring Boot app:

```text
POST {APP_PUBLIC_BASE_URL}/oid4vp/direct_post
```

Form-encoded or JSON is accepted.

Expected JSON shape:

```json
{
  "state": "generated-state",
  "vp_token": "{\"given_name\":\"Erika\",\"family_name\":\"Mustermann\",\"birth_date\":\"1990-01-01\",\"person_identifier\":\"DEMO-123\",\"nationality\":\"DE\",\"nonce\":\"generated-nonce\"}",
  "presentation_submission": {
    "id": "presentation-submission-id",
    "definition_id": "pid-identification",
    "descriptor_map": []
  }
}
```

For form posts use OID4VP-style names:

```text
state=...
vp_token=...
presentation_submission=...
```

## State And Nonce

- Return `state` exactly as received in the request object.
- Bind or include the generated `nonce` in the presentation when your wallet supports it.
- The demo verifier accepts a missing nonce in the `vp_token`, but rejects a mismatching nonce when present.

## Certificate Trust

Download demo trust material from:

```text
GET {APP_PUBLIC_BASE_URL}/certs/root-ca.pem
GET {APP_PUBLIC_BASE_URL}/certs/client-cert.pem
GET {APP_PUBLIC_BASE_URL}/certs/jwks.json
```

The request object is signed by the demo verifier/client key. The client certificate is signed by the demo root CA.

This trust material is demo-only.
