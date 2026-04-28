package com.example.qrgen.oid4vp;

import java.util.Map;

public record PresentationVerificationResult(boolean verified, Map<String, Object> claims, String failureReason) {

    public static PresentationVerificationResult verified(Map<String, Object> claims) {
        return new PresentationVerificationResult(true, claims, null);
    }

    public static PresentationVerificationResult failed(String reason) {
        return new PresentationVerificationResult(false, Map.of(), reason);
    }
}
