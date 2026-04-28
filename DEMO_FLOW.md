# Live Demo Flow

Use this script for a deployed Railway demo.

## 1. Open The App

Open:

```text
https://your-app.up.railway.app
```

Confirm the dashboard shows the public base URL matching Railway.

## 2. Dummy Login

Open `/login` and sign in with:

```text
demo / demo
```

This login is only for setup and certificate access.

## 3. Show Or Download Root Certificate

Open `/certificates`.

Show:

- root CA download
- client/verifier certificate download
- JWKS endpoint

Root CA URL:

```text
https://your-app.up.railway.app/certs/root-ca.pem
```

## 4. Start Wallet Login

Open `/wallet-login` and click `Generate QR`.

The app creates:

- `state`
- `nonce`
- signed request object
- public `request_uri`
- QR code

## 5. Scan QR

Scan the QR with the mobile wallet.

The QR should look like:

```text
openid4vp://authorize?client_id=demo-eudi-pid-verifier&client_id_scheme=x509_san_dns&request_uri=https://your-app.up.railway.app/oid4vp/requests/{id}/object.jwt
```

## 6. Wallet Posts PID Presentation

The wallet fetches the request object and posts the presentation to:

```text
https://your-app.up.railway.app/oid4vp/direct_post
```

Expected fields:

- `state`
- `vp_token`
- `presentation_submission`

## 7. App Verifies And Shows Profile

The QR page polls `/oid4vp/sessions/{id}/status`.

When the wallet response verifies, the browser session is upgraded to a PID-authenticated session and redirects to `/profile`.

The profile page shows verified PID claims:

- `given_name`
- `family_name`
- `birth_date`
- `person_identifier`
- `nationality` when requested
