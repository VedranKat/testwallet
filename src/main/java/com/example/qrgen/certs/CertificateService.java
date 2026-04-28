package com.example.qrgen.certs;

import com.example.qrgen.config.DemoProperties;
import jakarta.annotation.PostConstruct;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class CertificateService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final DemoProperties properties;
    private CertificateMaterial material;

    public CertificateService(DemoProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void initialize() {
        try {
            Path certDir = Path.of(properties.getCertificateOutputDir());
            Files.createDirectories(certDir);
            this.material = hasConfiguredPemMaterial() ? loadConfiguredMaterial(certDir) : generateMaterial(certDir);
        } catch (Exception ex) {
            throw new IllegalStateException("Could not generate demo certificate material", ex);
        }
    }

    public CertificateMaterial material() {
        return material;
    }

    public byte[] rootCertificatePem() {
        return read(material.rootCertificatePath());
    }

    public byte[] clientCertificatePem() {
        return read(material.clientCertificatePath());
    }

    private CertificateMaterial generateMaterial(Path certDir) throws Exception {
        KeyPair rootKeyPair = generateRsaKeyPair();
        KeyPair clientKeyPair = generateRsaKeyPair();

        X509Certificate rootCert = createRootCertificate(rootKeyPair);
        X509Certificate clientCert = createClientCertificate(clientKeyPair, rootKeyPair, rootCert);

        Path rootCertPath = certDir.resolve("demo-root-ca.pem");
        Path rootKeyPath = certDir.resolve("demo-root-ca-key.pem");
        Path clientCertPath = certDir.resolve("demo-client-cert.pem");
        Path clientKeyPath = certDir.resolve("demo-client-key.pem");

        writePem(rootCertPath, rootCert);
        writePem(rootKeyPath, rootKeyPair.getPrivate());
        writePem(clientCertPath, clientCert);
        writePem(clientKeyPath, clientKeyPair.getPrivate());

        return new CertificateMaterial(rootKeyPair, rootCert, clientKeyPair, clientCert, rootCertPath, rootKeyPath, clientCertPath, clientKeyPath);
    }

    private CertificateMaterial loadConfiguredMaterial(Path certDir) throws Exception {
        Path rootCertPath = certDir.resolve("demo-root-ca.pem");
        Path rootKeyPath = certDir.resolve("demo-root-ca-key.pem");
        Path clientCertPath = certDir.resolve("demo-client-cert.pem");
        Path clientKeyPath = certDir.resolve("demo-client-key.pem");

        Files.writeString(rootCertPath, normalizePem(properties.getRootCaPem()), StandardCharsets.UTF_8);
        Files.writeString(rootKeyPath, normalizePem(properties.getRootCaKeyPem()), StandardCharsets.UTF_8);
        Files.writeString(clientCertPath, normalizePem(properties.getClientCertPem()), StandardCharsets.UTF_8);
        Files.writeString(clientKeyPath, normalizePem(properties.getClientKeyPem()), StandardCharsets.UTF_8);

        X509Certificate rootCert = parseCertificate(properties.getRootCaPem());
        X509Certificate clientCert = parseCertificate(properties.getClientCertPem());
        PrivateKey rootPrivateKey = parsePrivateKey(properties.getRootCaKeyPem());
        PrivateKey clientPrivateKey = parsePrivateKey(properties.getClientKeyPem());

        return new CertificateMaterial(
                new KeyPair(rootCert.getPublicKey(), rootPrivateKey),
                rootCert,
                new KeyPair(clientCert.getPublicKey(), clientPrivateKey),
                clientCert,
                rootCertPath,
                rootKeyPath,
                clientCertPath,
                clientKeyPath);
    }

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048, RANDOM);
        return generator.generateKeyPair();
    }

    private X509Certificate createRootCertificate(KeyPair keyPair) throws Exception {
        X500Name subject = new X500Name("CN=Demo EUDI PID Root CA,O=Demo Only,C=EU");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject,
                randomSerial(),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                subject,
                keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return sign(builder, keyPair);
    }

    private X509Certificate createClientCertificate(KeyPair clientKeyPair, KeyPair rootKeyPair, X509Certificate rootCert) throws Exception {
        X500Name issuer = new X500Name(rootCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name("CN=" + properties.getClientId() + ",O=Demo Only,C=EU");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                randomSerial(),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(180, ChronoUnit.DAYS)),
                subject,
                clientKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        builder.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName(GeneralName.dNSName, properties.getClientId())));
        return sign(builder, rootKeyPair);
    }

    private X509Certificate sign(JcaX509v3CertificateBuilder builder, KeyPair signerKeyPair) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(signerKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(holder);
    }

    private BigInteger randomSerial() {
        return new BigInteger(160, RANDOM).abs();
    }

    private void writePem(Path path, Object value) throws IOException {
        try (StringWriter stringWriter = new StringWriter(); JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter)) {
            pemWriter.writeObject(value);
            pemWriter.flush();
            Files.writeString(path, stringWriter.toString(), StandardCharsets.UTF_8);
        }
    }

    private boolean hasConfiguredPemMaterial() {
        return hasText(properties.getRootCaPem())
                && hasText(properties.getRootCaKeyPem())
                && hasText(properties.getClientCertPem())
                && hasText(properties.getClientKeyPem());
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String normalizePem(String pem) {
        return pem.replace("\\n", "\n").trim() + "\n";
    }

    private X509Certificate parseCertificate(String pem) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) factory.generateCertificate(new java.io.ByteArrayInputStream(normalizePem(pem).getBytes(StandardCharsets.UTF_8)));
    }

    private PrivateKey parsePrivateKey(String pem) throws Exception {
        try (PEMParser parser = new PEMParser(new StringReader(normalizePem(pem)))) {
            Object object = parser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            if (object instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            }
            if (object instanceof org.bouncycastle.asn1.pkcs.PrivateKeyInfo privateKeyInfo) {
                return converter.getPrivateKey(privateKeyInfo);
            }
            throw new IllegalArgumentException("Unsupported PEM private key format.");
        }
    }

    private byte[] read(Path path) {
        try {
            return Files.readAllBytes(path);
        } catch (IOException ex) {
            throw new IllegalStateException("Could not read certificate file " + path, ex);
        }
    }
}
