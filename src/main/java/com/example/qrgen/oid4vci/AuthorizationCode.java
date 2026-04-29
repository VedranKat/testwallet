package com.example.qrgen.oid4vci;

import java.time.Instant;

public record AuthorizationCode(
        String code,
        String clientId,
        String redirectUri,
        String scope,
        String codeChallenge,
        Instant expiresAt
) {
}
