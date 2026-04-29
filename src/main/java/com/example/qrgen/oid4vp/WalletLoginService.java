package com.example.qrgen.oid4vp;

import com.example.qrgen.certs.CertificateService;
import com.example.qrgen.config.DemoProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDHDecrypter;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
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
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Service
public class WalletLoginService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DemoProperties properties;
    private final CertificateService certificateService;
    private final PresentationVerificationService verificationService;
    private final ObjectMapper objectMapper;
    private final Map<String, WalletLoginSession> sessions = new ConcurrentHashMap<>();
    private final Map<String, String> statesToSessionIds = new ConcurrentHashMap<>();
    private final Map<String, ECKey> responseDecryptionKeys = new ConcurrentHashMap<>();

    public WalletLoginService(DemoProperties properties, CertificateService certificateService, PresentationVerificationService verificationService, ObjectMapper objectMapper) {
        this.properties = properties;
        this.certificateService = certificateService;
        this.verificationService = verificationService;
        this.objectMapper = objectMapper;
    }

    public WalletLoginSession createSession(boolean includeNationality) {
        String id = UUID.randomUUID().toString();
        String state = randomUrlValue();
        String nonce = randomUrlValue();
        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusSeconds(properties.getRequestTtlSeconds());
        String publicBaseUrl = normalizedPublicBaseUrl();
        String requestUri = publicBaseUrl + "/wallet/request.jwt/" + state;
        String responseUri = publicBaseUrl + "/wallet/direct_post/" + state;
        List<String> claims = requestedClaims(includeNationality);
        ECKey responseEncryptionKey = generateResponseEncryptionKey();
        responseDecryptionKeys.put(state, responseEncryptionKey);
        String clientId = x509HashClientId();
        Map<String, Object> payload = oid4vpPayload(id, state, nonce, responseUri, issuedAt, expiresAt, claims, clientId, responseEncryptionKey);
        String signedObject = signPayload(payload, issuedAt, expiresAt);
        String qrUri = buildQrUri(requestUri, clientId);

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

    public WalletLoginSession verifyEncryptedDirectPost(String pathState, String formState, String encryptedResponse) {
        if (pathState == null || formState == null || !pathState.equals(formState)) {
            throw new IllegalArgumentException("Path state and form state do not match.");
        }
        DirectPostRequest request = decryptDirectPostJwt(pathState, encryptedResponse);
        return verifyDirectPost(request);
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

    public Optional<WalletLoginSession> findByRequestState(String state) {
        return findByState(state);
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

    private Map<String, Object> oid4vpPayload(String id, String state, String nonce, String responseUri, Instant issuedAt, Instant expiresAt,
                                             List<String> claims, String clientId, ECKey responseEncryptionKey) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("response_uri", responseUri);
        payload.put("aud", "https://self-issued.me/v2");
        payload.put("response_type", "vp_token");
        payload.put("state", state);
        payload.put("iat", issuedAt.getEpochSecond());
        payload.put("exp", expiresAt.getEpochSecond());
        payload.put("jti", id);
        payload.put("nonce", nonce);
        payload.put("client_id", clientId);
        payload.put("response_mode", "direct_post.jwt");
        payload.put("dcql_query", dcqlQuery(claims));
        payload.put("client_metadata", clientMetadata(responseEncryptionKey));
        return payload;
    }

    private Map<String, Object> dcqlQuery(List<String> claims) {
        Map<String, Object> credential = new LinkedHashMap<>();
        credential.put("id", "query_0");
        credential.put("format", "dc+sd-jwt");
        credential.put("meta", Map.of("vct_values", List.of("urn:eudi:pid:1")));
        credential.put("claims", claims.stream()
                .map(claim -> Map.of("path", List.of(claim)))
                .toList());
        return Map.of("credentials", List.of(credential));
    }

    private Map<String, Object> clientMetadata(ECKey responseEncryptionKey) {
        Map<String, Object> publicJwk = responseEncryptionKey.toPublicJWK().toJSONObject();
        publicJwk.put("use", "enc");
        publicJwk.put("alg", "ECDH-ES");
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("jwks", Map.of("keys", List.of(publicJwk)));
        metadata.put("vp_formats_supported", Map.of("dc+sd-jwt", Map.of(
                "sd-jwt_alg_values", List.of("ES256", "ES384", "ES512"),
                "kb-jwt_alg_values", List.of("ES256", "ES384", "ES512"))));
        metadata.put("encrypted_response_enc_values_supported", List.of("A128GCM", "A256GCM"));
        return metadata;
    }

    private String signPayload(Map<String, Object> payload, Instant issuedAt, Instant expiresAt) {
        try {
            X509Certificate cert = certificateService.material().clientCertificate();
            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                    .type(new JOSEObjectType("oauth-authz-req+jwt"))
                    .x509CertChain(List.of(com.nimbusds.jose.util.Base64.encode(cert.getEncoded())))
                    .build();

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .audience("https://self-issued.me/v2")
                    .issueTime(Date.from(issuedAt))
                    .expirationTime(Date.from(expiresAt));
            payload.forEach(claims::claim);

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new ECDSASigner((ECPrivateKey) certificateService.material().clientKeyPair().getPrivate()));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not sign OID4VP request object", ex);
        }
    }

    private String buildQrUri(String requestUri, String clientId) {
        if ("https".equalsIgnoreCase(properties.getQrUriMode())) {
            return requestUri;
        }
        return "eudi-openid4vp://?client_id=" + encode(clientId) + "&request_uri=" + encode(requestUri);
    }

    private List<String> requestedClaims(boolean includeNationality) {
        return List.of("family_name", "given_name");
    }

    private DirectPostRequest decryptDirectPostJwt(String state, String encryptedResponse) {
        if (encryptedResponse == null || encryptedResponse.isBlank()) {
            throw new IllegalArgumentException("Missing encrypted response.");
        }
        ECKey decryptionKey = responseDecryptionKeys.get(state);
        if (decryptionKey == null) {
            throw new IllegalArgumentException("No response decryption key for state.");
        }
        try {
            JWEObject jwe = JWEObject.parse(encryptedResponse);
            jwe.decrypt(new ECDHDecrypter(decryptionKey));
            Map<String, Object> payload = objectMapper.readValue(jwe.getPayload().toString(), new TypeReference<>() {
            });
            return new DirectPostRequest(String.valueOf(payload.get("state")), payload.get("vp_token"), Map.of());
        } catch (Exception ex) {
            throw new IllegalArgumentException("Could not decrypt direct_post.jwt response.", ex);
        }
    }

    private ECKey generateResponseEncryptionKey() {
        try {
            return new ECKeyGenerator(Curve.P_256)
                    .keyUse(KeyUse.ENCRYPTION)
                    .algorithm(JWEAlgorithm.ECDH_ES)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
        } catch (Exception ex) {
            throw new IllegalStateException("Could not generate response encryption key", ex);
        }
    }

    private String x509HashClientId() {
        try {
            byte[] der = certificateService.material().clientCertificate().getEncoded();
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(der);
            return "x509_hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception ex) {
            throw new IllegalStateException("Could not compute x509_hash client_id", ex);
        }
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
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
