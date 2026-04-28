package com.example.qrgen.oid4vp;

import com.example.qrgen.certs.CertificateService;
import com.example.qrgen.config.DemoProperties;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class WalletLoginService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DemoProperties properties;
    private final CertificateService certificateService;
    private final PresentationVerificationService verificationService;
    private final Map<String, WalletLoginSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, String> statesToSessionIds = new ConcurrentHashMap<>();

    public WalletLoginService(DemoProperties properties, CertificateService certificateService, PresentationVerificationService verificationService) {
        this.properties = properties;
        this.certificateService = certificateService;
        this.verificationService = verificationService;
    }

    public WalletLoginSession createSession(boolean includeNationality) {
        String id = UUID.randomUUID().toString();
        String state = randomUrlValue();
        String nonce = randomUrlValue();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(properties.getRequestTtlSeconds());
        String publicBaseUrl = normalizedPublicBaseUrl();
        String requestUri = publicBaseUrl + "/oid4vp/requests/" + id + "/object.jwt";
        String responseUri = publicBaseUrl + "/oid4vp/direct_post";
        List<String> claims = requestedClaims(includeNationality);
        Map<String, Object> payload = oid4vpPayload(id, state, nonce, responseUri, issuedAt, expiresAt, claims);
        String signedObject = signPayload(payload, issuedAt, expiresAt);
        String qrUri = buildQrUri(requestUri);

        WalletLoginSession session = new WalletLoginSession(id, state, nonce, requestUri, qrUri, responseUri,
                signedObject, payload, claims, issuedAt, expiresAt, WalletLoginStatus.PENDING, Map.of(), null);
        sessions.put(id, session);
        statesToSessionIds.put(state, id);
        return session;
    }

    public Optional<WalletLoginSession> find(String id) {
        return Optional.ofNullable(sessions.get(id)).map(this::expireIfNeeded);
    }

    public Optional<WalletLoginSession> findByState(String state) {
        return Optional.ofNullable(statesToSessionIds.get(state)).flatMap(this::find);
    }

    public WalletLoginSession verifyDirectPost(DirectPostRequest post) {
        WalletLoginSession session = findByState(post.state()).orElseThrow(() -> new IllegalArgumentException("Unknown state."));
        if (session.status() != WalletLoginStatus.PENDING) {
            return session;
        }
        if (Instant.now().isAfter(session.expiresAt())) {
            return update(session.withStatus(WalletLoginStatus.EXPIRED, null, "Login request expired."));
        }
        PresentationVerificationResult result = verificationService.verify(session, post);
        if (result.verified()) {
            return update(session.withStatus(WalletLoginStatus.VERIFIED, result.claims(), null));
        }
        return update(session.withStatus(WalletLoginStatus.FAILED, null, result.failureReason()));
    }

    public Map<String, Object> decodedJwtPayload(String compactJwt) {
        try {
            return new LinkedHashMap<>(SignedJWT.parse(compactJwt).getJWTClaimsSet().getClaims());
        } catch (ParseException ex) {
            throw new IllegalArgumentException("Invalid signed request object", ex);
        }
    }

    private WalletLoginSession expireIfNeeded(WalletLoginSession session) {
        if (session.status() == WalletLoginStatus.PENDING && Instant.now().isAfter(session.expiresAt())) {
            return update(session.withStatus(WalletLoginStatus.EXPIRED, null, "Login request expired."));
        }
        return session;
    }

    private WalletLoginSession update(WalletLoginSession session) {
        sessions.put(session.id(), session);
        return session;
    }

    private Map<String, Object> oid4vpPayload(String id, String state, String nonce, String responseUri, Instant issuedAt, Instant expiresAt, List<String> claims) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("iss", properties.getClientId());
        payload.put("client_id", properties.getClientId());
        payload.put("client_id_scheme", properties.getClientIdScheme());
        payload.put("aud", "https://self-issued.me/v2");
        payload.put("iat", issuedAt.getEpochSecond());
        payload.put("exp", expiresAt.getEpochSecond());
        payload.put("jti", id);
        payload.put("response_type", "vp_token");
        payload.put("response_mode", "direct_post");
        payload.put("response_uri", responseUri);
        payload.put("nonce", nonce);
        payload.put("state", state);
        payload.put("presentation_definition", presentationDefinition(claims));
        return payload;
    }

    private Map<String, Object> presentationDefinition(List<String> claims) {
        Map<String, Object> definition = new LinkedHashMap<>();
        definition.put("id", "pid-identification");
        definition.put("name", "PID identification");
        definition.put("purpose", "PID-based identification for login");

        Map<String, Object> descriptor = new LinkedHashMap<>();
        descriptor.put("id", "eu-pid");
        descriptor.put("name", "EU PID");
        descriptor.put("purpose", "Request Person Identification Data from an EUDI Wallet");
        descriptor.put("format", Map.of("vc+sd-jwt", Map.of("sd-jwt_alg_values", List.of("ES256", "ES384"), "kb-jwt_alg_values", List.of("ES256"))));
        descriptor.put("constraints", Map.of("fields", claims.stream()
                .map(claim -> Map.of("path", List.of("$." + claim), "intent_to_retain", false))
                .toList()));

        definition.put("input_descriptors", List.of(descriptor));
        return definition;
    }

    private String signPayload(Map<String, Object> payload, Instant issuedAt, Instant expiresAt) {
        try {
            X509Certificate cert = certificateService.material().clientCertificate();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(new JOSEObjectType("oauth-authz-req+jwt"))
                    .keyID(properties.getClientId())
                    .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(cert.getEncoded())))
                    .build();

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(properties.getClientId())
                    .audience("https://self-issued.me/v2")
                    .issueTime(Date.from(issuedAt))
                    .expirationTime(Date.from(expiresAt));
            payload.forEach(claims::claim);

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new RSASSASigner((RSAPrivateKey) certificateService.material().clientKeyPair().getPrivate()));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not sign OID4VP request object", ex);
        }
    }

    private String buildQrUri(String requestUri) {
        if ("https".equalsIgnoreCase(properties.getQrUriMode())) {
            return requestUri;
        }
        return UriComponentsBuilder.fromUriString("openid4vp://authorize")
                .queryParam("client_id", properties.getClientId())
                .queryParam("client_id_scheme", properties.getClientIdScheme())
                .queryParam("request_uri", requestUri)
                .build()
                .toUriString();
    }

    private List<String> requestedClaims(boolean includeNationality) {
        List<String> claims = new ArrayList<>(List.of("given_name", "family_name", "birth_date", "person_identifier"));
        if (includeNationality) {
            claims.add("nationality");
        }
        return claims;
    }

    private String normalizedPublicBaseUrl() {
        String value = properties.getPublicBaseUrl();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private String randomUrlValue() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
