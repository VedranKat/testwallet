package com.example.qrgen.web;

import com.example.qrgen.certs.CertificateService;
import com.example.qrgen.config.DemoProperties;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.interfaces.RSAPublicKey;
import java.util.Map;

@RestController
public class CertificateController {

    private final CertificateService certificateService;
    private final DemoProperties properties;

    public CertificateController(CertificateService certificateService, DemoProperties properties) {
        this.certificateService = certificateService;
        this.properties = properties;
    }

    @GetMapping("/certs/root-ca.pem")
    ResponseEntity<byte[]> rootCertificate() {
        return WebController.pemDownload(certificateService.rootCertificatePem(), "demo-root-ca.pem");
    }

    @GetMapping("/certs/client-cert.pem")
    ResponseEntity<byte[]> clientCertificate() {
        return WebController.pemDownload(certificateService.clientCertificatePem(), "demo-client-cert.pem");
    }

    @GetMapping("/certs/jwks.json")
    Map<String, Object> jwks() {
        RSAKey key = new RSAKey.Builder((RSAPublicKey) certificateService.material().clientKeyPair().getPublic())
                .keyID(properties.getClientId())
                .build();
        return new JWKSet(key).toJSONObject();
    }
}
