package com.example.qrgen.oid4vp;

import java.time.Instant;
import java.util.List;
import java.util.Map;

public record WalletLoginSession(
        String id,
        String state,
        String nonce,
        String requestUri,
        String qrUri,
        String responseUri,
        String signedRequestObject,
        Map<String, Object> payload,
        List<String> requestedClaims,
        Instant issuedAt,
        Instant expiresAt,
        WalletLoginStatus status,
        Map<String, Object> verifiedClaims,
        String failureReason
) {

    public WalletLoginSession withStatus(WalletLoginStatus nextStatus, Map<String, Object> claims, String reason) {
        return new WalletLoginSession(id, state, nonce, requestUri, qrUri, responseUri, signedRequestObject, payload,
                requestedClaims, issuedAt, expiresAt, nextStatus, claims == null ? Map.of() : Map.copyOf(claims), reason);
    }
}
