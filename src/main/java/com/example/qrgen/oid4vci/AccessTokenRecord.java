package com.example.qrgen.oid4vci;

import java.time.Instant;

public record AccessTokenRecord(
        String token,
        String clientId,
        String scope,
        Instant expiresAt
) {
}
