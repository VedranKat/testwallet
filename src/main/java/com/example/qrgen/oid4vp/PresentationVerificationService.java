package com.example.qrgen.oid4vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class PresentationVerificationService {

    private final ObjectMapper objectMapper;

    public PresentationVerificationService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public PresentationVerificationResult verify(WalletLoginSession session, DirectPostRequest post) {
        if (post.state() == null || !post.state().equals(session.state())) {
            return PresentationVerificationResult.failed("State does not match a pending login session.");
        }
        if (post.vpToken() == null || (post.vpToken() instanceof String value && value.isBlank())) {
            return PresentationVerificationResult.failed("Missing vp_token.");
        }

        Map<String, Object> tokenClaims = parseVpToken(post.vpToken());
        if (tokenClaims.isEmpty()) {
            return PresentationVerificationResult.failed("Could not parse vp_token as JSON or JWT claims.");
        }

        Optional<Object> responseNonce = findValue(tokenClaims, "nonce");
        if (responseNonce.isPresent() && !session.nonce().equals(String.valueOf(responseNonce.get()))) {
            return PresentationVerificationResult.failed("Nonce does not match the generated request.");
        }

        Map<String, Object> pidClaims = new LinkedHashMap<>();
        for (String claim : session.requestedClaims()) {
            Optional<Object> value = findValue(tokenClaims, claim);
            if (value.isEmpty()) {
                return PresentationVerificationResult.failed("Missing required PID claim: " + claim);
            }
            pidClaims.put(claim, value.get());
        }
        return PresentationVerificationResult.verified(pidClaims);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> parseVpToken(Object vpToken) {
        try {
            if (vpToken instanceof Map<?, ?> map) {
                return new LinkedHashMap<>((Map<String, Object>) map);
            }
            String serialized = String.valueOf(vpToken);
            if (serialized.trim().startsWith("{")) {
                return objectMapper.readValue(serialized, new TypeReference<>() {
                });
            }
            return new LinkedHashMap<>(SignedJWT.parse(serialized).getJWTClaimsSet().getClaims());
        } catch (Exception ex) {
            return Map.of();
        }
    }

    @SuppressWarnings("unchecked")
    private Optional<Object> findValue(Object source, String key) {
        if (source instanceof Map<?, ?> map) {
            if (map.containsKey(key)) {
                return Optional.ofNullable(map.get(key));
            }
            for (Object value : map.values()) {
                Optional<Object> nested = findValue(value, key);
                if (nested.isPresent()) {
                    return nested;
                }
            }
        }
        if (source instanceof List<?> list) {
            for (Object item : list) {
                Optional<Object> nested = findValue(item, key);
                if (nested.isPresent()) {
                    return nested;
                }
            }
        }
        return Optional.empty();
    }
}
