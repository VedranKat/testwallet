package com.example.qrgen.certs;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;

public record CertificateMaterial(
        KeyPair rootKeyPair,
        X509Certificate rootCertificate,
        KeyPair clientKeyPair,
        X509Certificate clientCertificate,
        Path rootCertificatePath,
        Path rootKeyPath,
        Path clientCertificatePath,
        Path clientKeyPath
) {
}
