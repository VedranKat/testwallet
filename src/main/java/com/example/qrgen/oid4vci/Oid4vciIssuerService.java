package com.example.qrgen.oid4vci;

import com.example.qrgen.certs.CertificateService;
import com.example.qrgen.config.DemoProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
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
import java.util.zip.Deflater;

@Service
public class Oid4vciIssuerService {

    public static final String WALLET_CLIENT_ID = "wallet-dev";
    public static final String WALLET_REDIRECT_URI = "eudi-wallet://authorize";
    public static final String PID_SCOPE = "eu.europa.ec.eudi.pid_vc_sd_jwt";
    public static final String PID_CONFIGURATION_ID = "eu.europa.ec.eudi.pid_vc_sd_jwt";
    public static final String PID_VCT = "urn:eudi:pid:1";

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DemoProperties properties;
    private final CertificateService certificateService;
    private final ObjectMapper objectMapper;
    private final Map<String, ParRequest> parRequests = new ConcurrentHashMap<>();
    private final Map<String, AuthorizationCode> authorizationCodes = new ConcurrentHashMap<>();
    private final Map<String, AccessTokenRecord> accessTokens = new ConcurrentHashMap<>();

    public Oid4vciIssuerService(DemoProperties properties, CertificateService certificateService, ObjectMapper objectMapper) {
        this.properties = properties;
        this.certificateService = certificateService;
        this.objectMapper = objectMapper;
    }

    public Map<String, Object> credentialIssuerMetadata() {
        String baseUrl = baseUrl();
        Map<String, Object> configuration = new LinkedHashMap<>();
        configuration.put("format", "dc+sd-jwt");
        configuration.put("scope", PID_SCOPE);
        configuration.put("vct", PID_VCT);
        configuration.put("cryptographic_binding_methods_supported", List.of("jwk"));
        configuration.put("credential_signing_alg_values_supported", List.of("ES256"));
        configuration.put("proof_types_supported", Map.of("jwt", Map.of("proof_signing_alg_values_supported", List.of("ES256"))));
        return Map.of(
                "credential_issuer", baseUrl,
                "authorization_servers", List.of(baseUrl),
                "credential_endpoint", baseUrl + "/credential",
                "credential_configurations_supported", Map.of(PID_CONFIGURATION_ID, configuration));
    }

    public Map<String, Object> authorizationServerMetadata() {
        String baseUrl = baseUrl();
        return Map.of(
                "issuer", baseUrl,
                "authorization_endpoint", baseUrl + "/authorize",
                "token_endpoint", baseUrl + "/token",
                "pushed_authorization_request_endpoint", baseUrl + "/par",
                "response_types_supported", List.of("code"),
                "grant_types_supported", List.of("authorization_code"),
                "code_challenge_methods_supported", List.of("S256"),
                "scopes_supported", List.of(PID_SCOPE));
    }

    public String credentialOfferUri() {
        return "openid-credential-offer://?credential_offer_uri=" + encode(baseUrl() + "/credential-offer");
    }

    public Map<String, Object> credentialOffer() {
        return Map.of(
                "credential_issuer", baseUrl(),
                "credential_configuration_ids", List.of(PID_CONFIGURATION_ID),
                "grants", Map.of("authorization_code", Map.of("issuer_state", UUID.randomUUID().toString())));
    }

    public ParRequest createPar(String clientId, String responseType, String redirectUri, String scope, String state,
                                String codeChallenge, String codeChallengeMethod) {
        if (!WALLET_CLIENT_ID.equals(clientId)) {
            throw new IllegalArgumentException("Unsupported client_id.");
        }
        if (!"code".equals(responseType)) {
            throw new IllegalArgumentException("Unsupported response_type.");
        }
        if (!WALLET_REDIRECT_URI.equals(redirectUri)) {
            throw new IllegalArgumentException("Unsupported redirect_uri.");
        }
        if (!PID_SCOPE.equals(scope)) {
            throw new IllegalArgumentException("Unsupported scope.");
        }
        if (!"S256".equals(codeChallengeMethod)) {
            throw new IllegalArgumentException("Only PKCE S256 is supported.");
        }
        String requestUri = "urn:uuid:" + UUID.randomUUID();
        ParRequest request = new ParRequest(requestUri, clientId, redirectUri, scope, state, codeChallenge, Instant.now().plusSeconds(3600));
        parRequests.put(requestUri, request);
        return request;
    }

    public Optional<ParRequest> findPar(String requestUri) {
        ParRequest request = parRequests.get(requestUri);
        if (request == null || Instant.now().isAfter(request.expiresAt())) {
            return Optional.empty();
        }
        return Optional.of(request);
    }

    public String approve(String requestUri, String clientId) {
        ParRequest request = findPar(requestUri).orElseThrow(() -> new IllegalArgumentException("Unknown or expired request_uri."));
        if (!request.clientId().equals(clientId)) {
            throw new IllegalArgumentException("client_id does not match PAR request.");
        }
        String code = randomUrlValue();
        authorizationCodes.put(code, new AuthorizationCode(code, request.clientId(), request.redirectUri(), request.scope(),
                request.codeChallenge(), Instant.now().plusSeconds(300)));
        return code;
    }

    public Map<String, Object> exchangeToken(String grantType, String code, String codeVerifier, String redirectUri, String clientId) {
        if (!"authorization_code".equals(grantType)) {
            throw new IllegalArgumentException("Unsupported grant_type.");
        }
        AuthorizationCode authorizationCode = authorizationCodes.remove(code);
        if (authorizationCode == null || Instant.now().isAfter(authorizationCode.expiresAt())) {
            throw new IllegalArgumentException("Unknown or expired authorization code.");
        }
        if (!authorizationCode.clientId().equals(clientId) || !authorizationCode.redirectUri().equals(redirectUri)) {
            throw new IllegalArgumentException("Authorization code binding mismatch.");
        }
        if (!authorizationCode.codeChallenge().equals(pkceChallenge(codeVerifier))) {
            throw new IllegalArgumentException("PKCE verification failed.");
        }
        String accessToken = signedToken(clientId, authorizationCode.scope(), 3600);
        String refreshToken = signedToken(clientId, authorizationCode.scope(), 86400);
        accessTokens.put(accessToken, new AccessTokenRecord(accessToken, clientId, authorizationCode.scope(), Instant.now().plusSeconds(3600)));
        return Map.of(
                "access_token", accessToken,
                "expires_in", 3600,
                "refresh_token", refreshToken,
                "scope", authorizationCode.scope(),
                "token_type", "Bearer");
    }

    @SuppressWarnings("unchecked")
    public Map<String, Object> issueCredential(String authorizationHeader, Map<String, Object> request) {
        AccessTokenRecord token = requireAccessToken(authorizationHeader);
        Object configurationId = request.get("credential_configuration_id");
        if (!PID_CONFIGURATION_ID.equals(configurationId)) {
            throw new IllegalArgumentException("Unsupported credential_configuration_id.");
        }
        Map<String, Object> proof = (Map<String, Object>) request.get("proof");
        if (proof == null || !"jwt".equals(proof.get("proof_type")) || proof.get("jwt") == null) {
            throw new IllegalArgumentException("Missing jwt proof.");
        }
        Map<String, Object> holderJwk = holderJwk(String.valueOf(proof.get("jwt")));
        String credential = sdJwtCredential(token.clientId(), holderJwk);
        return Map.of(
                "credentials", List.of(Map.of("credential", credential)),
                "notification_id", UUID.randomUUID().toString());
    }

    public String statusListJwt() {
        try {
            Instant now = Instant.now();
            byte[] statusBytes = new byte[16 * 1024];
            byte[] compressed = deflate(statusBytes);
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(baseUrl())
                    .subject(baseUrl() + "/status-list.jwt")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(86400)))
                    .claim("ttl", 3600)
                    .claim("status_list", Map.of(
                            "bits", 1,
                            "lst", Base64.getUrlEncoder().withoutPadding().encodeToString(compressed)))
                    .build();
            return signJwt(new JOSEObjectType("statuslist+jwt"), claims);
        } catch (Exception ex) {
            throw new IllegalStateException("Could not create status list JWT", ex);
        }
    }

    private AccessTokenRecord requireAccessToken(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Missing bearer token.");
        }
        String tokenValue = authorizationHeader.substring("Bearer ".length());
        AccessTokenRecord token = accessTokens.get(tokenValue);
        if (token == null || Instant.now().isAfter(token.expiresAt())) {
            throw new IllegalArgumentException("Invalid or expired access token.");
        }
        return token;
    }

    private Map<String, Object> holderJwk(String proofJwt) {
        try {
            SignedJWT jwt = SignedJWT.parse(proofJwt);
            Object jwk = jwt.getHeader().toJSONObject().get("jwk");
            if (jwk instanceof Map<?, ?> map) {
                return new LinkedHashMap<>((Map<String, Object>) map);
            }
            throw new IllegalArgumentException("PoP proof JWT header does not contain jwk.");
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid PoP proof JWT.", ex);
        }
    }

    private String sdJwtCredential(String subject, Map<String, Object> holderJwk) {
        try {
            Instant now = Instant.now();
            List<String> disclosures = new ArrayList<>();
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("iss", baseUrl());
            payload.put("sub", subject);
            payload.put("iat", now.getEpochSecond());
            payload.put("exp", now.plusSeconds(90L * 24L * 60L * 60L).getEpochSecond());
            payload.put("vct", PID_VCT);
            payload.put("_sd_alg", "sha-256");
            payload.put("cnf", Map.of("jwk", holderJwk));
            payload.put("status", Map.of("status_list", Map.of("idx", RANDOM.nextInt(1000), "uri", baseUrl() + "/status-list.jwt")));

            List<String> digests = new ArrayList<>();
            for (Map.Entry<String, Object> entry : pidClaims().entrySet()) {
                String disclosure = disclosure(entry.getKey(), entry.getValue());
                disclosures.add(disclosure);
                digests.add(disclosureDigest(disclosure));
            }
            payload.put("_sd", digests);

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder();
            payload.forEach(claims::claim);
            String jwt = signJwt(new JOSEObjectType("dc+sd-jwt"), claims.build());
            return jwt + "~" + String.join("~", disclosures) + "~";
        } catch (Exception ex) {
            throw new IllegalStateException("Could not issue SD-JWT VC.", ex);
        }
    }

    private Map<String, Object> pidClaims() {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("family_name", "Demo");
        claims.put("given_name", "Wallet");
        claims.put("birthdate", "1990-01-01");
        claims.put("nationalities", List.of("HR"));
        claims.put("place_of_birth", Map.of("country", "HR", "locality", "Zagreb", "region", "Grad Zagreb"));
        claims.put("issuing_authority", "Demo PID Issuer");
        claims.put("issuing_country", "HR");
        claims.put("date_of_issuance", "2026-04-29");
        claims.put("date_of_expiry", "2027-04-29");
        return claims;
    }

    private String disclosure(String name, Object value) throws Exception {
        List<Object> disclosure = List.of(randomUrlValue(), name, value);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(objectMapper.writeValueAsBytes(disclosure));
    }

    private String disclosureDigest(String disclosure) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(disclosure.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private String signedToken(String clientId, String scope, long ttlSeconds) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .issuer(baseUrl())
                    .subject(clientId)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(ttlSeconds)))
                    .claim("scope", scope)
                    .jwtID(UUID.randomUUID().toString())
                    .build();
            return signJwt(new JOSEObjectType("JWT"), claims);
        } catch (Exception ex) {
            throw new IllegalStateException("Could not sign token.", ex);
        }
    }

    private String signJwt(JOSEObjectType type, JWTClaimsSet claims) throws Exception {
        X509Certificate cert = certificateService.material().clientCertificate();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(type)
                .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(cert.getEncoded())))
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        jwt.sign(new ECDSASigner((ECPrivateKey) certificateService.material().clientKeyPair().getPrivate()));
        return jwt.serialize();
    }

    private String pkceChallenge(String codeVerifier) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Could not verify PKCE.", ex);
        }
    }

    private byte[] deflate(byte[] value) {
        Deflater deflater = new Deflater(Deflater.BEST_COMPRESSION);
        deflater.setInput(value);
        deflater.finish();
        byte[] output = new byte[512];
        int length = deflater.deflate(output);
        byte[] result = new byte[length];
        System.arraycopy(output, 0, result, 0, length);
        return result;
    }

    private String baseUrl() {
        String value = properties.getPublicBaseUrl();
        return value.endsWith("/") ? value.substring(0, value.length() - 1) : value;
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private String randomUrlValue() {
        byte[] bytes = new byte[24];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
