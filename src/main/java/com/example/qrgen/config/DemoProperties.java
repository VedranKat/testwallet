package com.example.qrgen.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public class DemoProperties {

    private String publicBaseUrl;
    private String clientId;
    private String clientIdScheme;
    private String qrUriMode;
    private String certificateOutputDir;
    private String rootCaPem;
    private String rootCaKeyPem;
    private String clientCertPem;
    private String clientKeyPem;
    private boolean includeNationality;
    private long requestTtlSeconds;

    public String getPublicBaseUrl() {
        return publicBaseUrl;
    }

    public void setPublicBaseUrl(String publicBaseUrl) {
        this.publicBaseUrl = publicBaseUrl;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientIdScheme() {
        return clientIdScheme;
    }

    public void setClientIdScheme(String clientIdScheme) {
        this.clientIdScheme = clientIdScheme;
    }

    public String getQrUriMode() {
        return qrUriMode;
    }

    public void setQrUriMode(String qrUriMode) {
        this.qrUriMode = qrUriMode;
    }

    public String getCertificateOutputDir() {
        return certificateOutputDir;
    }

    public void setCertificateOutputDir(String certificateOutputDir) {
        this.certificateOutputDir = certificateOutputDir;
    }

    public String getRootCaPem() {
        return rootCaPem;
    }

    public void setRootCaPem(String rootCaPem) {
        this.rootCaPem = rootCaPem;
    }

    public String getRootCaKeyPem() {
        return rootCaKeyPem;
    }

    public void setRootCaKeyPem(String rootCaKeyPem) {
        this.rootCaKeyPem = rootCaKeyPem;
    }

    public String getClientCertPem() {
        return clientCertPem;
    }

    public void setClientCertPem(String clientCertPem) {
        this.clientCertPem = clientCertPem;
    }

    public String getClientKeyPem() {
        return clientKeyPem;
    }

    public void setClientKeyPem(String clientKeyPem) {
        this.clientKeyPem = clientKeyPem;
    }

    public boolean isIncludeNationality() {
        return includeNationality;
    }

    public void setIncludeNationality(boolean includeNationality) {
        this.includeNationality = includeNationality;
    }

    public long getRequestTtlSeconds() {
        return requestTtlSeconds;
    }

    public void setRequestTtlSeconds(long requestTtlSeconds) {
        this.requestTtlSeconds = requestTtlSeconds;
    }
}
