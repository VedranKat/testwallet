package com.example.qrgen.oid4vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.text.ParseException;
import java.util.Base64;
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

        Map<String, Object> tokenClaims;
        try {
            tokenClaims = parseVpToken(post.vpToken(), session);
        } catch (Exception ex) {
            return PresentationVerificationResult.failed(ex.getMessage());
        }
        if (tokenClaims.isEmpty()) {
            return PresentationVerificationResult.failed("Could not parse vp_token as DCQL SD-JWT presentation, JSON, or JWT claims.");
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
    private Map<String, Object> parseVpToken(Object vpToken, WalletLoginSession session) throws Exception {
        if (vpToken instanceof Map<?, ?> map) {
            Object queryResult = map.get("query_0");
            if (queryResult instanceof List<?> presentations && !presentations.isEmpty()) {
                return parseSdJwtPresentation(String.valueOf(presentations.getFirst()), session);
            }
            if (queryResult instanceof String presentation) {
                return parseSdJwtPresentation(presentation, session);
            }
            Object nestedToken = map.get("vp_token");
            if (nestedToken != null) {
                return parseVpToken(nestedToken, session);
            }
            return new LinkedHashMap<>((Map<String, Object>) map);
        }

        String serialized = String.valueOf(vpToken);
        if (serialized.trim().startsWith("{")) {
            Map<String, Object> parsed = objectMapper.readValue(serialized, new TypeReference<>() {
            });
            if (parsed.containsKey("query_0") || parsed.containsKey("vp_token")) {
                return parseVpToken(parsed, session);
            }
            return parsed;
        }
            if (serialized.contains("~")) {
                return parseSdJwtPresentation(serialized, session);
            }
        return new LinkedHashMap<>(SignedJWT.parse(serialized).getJWTClaimsSet().getClaims());
    }

    private Map<String, Object> parseSdJwtPresentation(String presentation, WalletLoginSession session) throws Exception {
        String[] parts = presentation.split("~", -1);
        if (parts.length < 3) {
            return Map.of();
        }

        String issuerJwt = parts[0];
        String kbJwt = parts[parts.length - 1].isBlank() ? null : parts[parts.length - 1];
        int disclosureEndExclusive = kbJwt == null ? parts.length : parts.length - 1;

        Map<String, Object> claims = new LinkedHashMap<>();
        for (int index = 1; index < disclosureEndExclusive; index++) {
            if (parts[index].isBlank()) {
                continue;
            }
            List<Object> disclosure = objectMapper.readValue(Base64.getUrlDecoder().decode(parts[index]), new TypeReference<>() {
            });
            if (disclosure.size() == 3 && disclosure.get(1) instanceof String claimName) {
                claims.put(claimName, disclosure.get(2));
            }
        }

        if (kbJwt != null) {
            SignedJWT keyBinding = SignedJWT.parse(kbJwt);
            Map<String, Object> kbClaims = keyBinding.getJWTClaimsSet().getClaims();
            Object nonce = kbClaims.get("nonce");
            if (nonce != null) {
                claims.put("nonce", nonce);
            }
            Object audience = kbClaims.get("aud");
            Object expectedAudience = session.payload().get("client_id");
            if (expectedAudience != null && audience != null && !audienceMatches(audience, String.valueOf(expectedAudience))) {
                throw new IllegalArgumentException("KB-JWT audience does not match request client_id.");
            }
            Object sdHash = kbClaims.get("sd_hash");
            if (sdHash != null && !String.valueOf(sdHash).equals(sdHash(issuerJwt, parts, disclosureEndExclusive))) {
                throw new IllegalArgumentException("KB-JWT sd_hash does not match presented disclosures.");
            }
        }

        claims.put("_sd_jwt_issuer_claims", SignedJWT.parse(issuerJwt).getJWTClaimsSet().getClaims());
        return claims;
    }

    private boolean audienceMatches(Object audience, String expectedAudience) {
        if (audience instanceof List<?> audiences) {
            return audiences.stream().anyMatch(value -> expectedAudience.equals(String.valueOf(value)));
        }
        return expectedAudience.equals(String.valueOf(audience));
    }

    private String sdHash(String issuerJwt, String[] parts, int disclosureEndExclusive) throws Exception {
        StringBuilder presented = new StringBuilder(issuerJwt).append('~');
        for (int index = 1; index < disclosureEndExclusive; index++) {
            if (!parts[index].isBlank()) {
                presented.append(parts[index]).append('~');
            }
        }
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(presented.toString().getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
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
