package com.example.qrgen.oid4vci;

import java.time.Instant;

public record ParRequest(
        String requestUri,
        String clientId,
        String redirectUri,
        String scope,
        String state,
        String codeChallenge,
        Instant expiresAt
) {
}
