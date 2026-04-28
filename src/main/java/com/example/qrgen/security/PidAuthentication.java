package com.example.qrgen.security;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.Map;

public class PidAuthentication extends UsernamePasswordAuthenticationToken {

    private final String sessionId;
    private final Map<String, Object> claims;

    public PidAuthentication(String sessionId, Map<String, Object> claims) {
        super("pid:" + claims.getOrDefault("person_identifier", sessionId), "N/A", List.of(new SimpleGrantedAuthority("ROLE_PID_USER")));
        this.sessionId = sessionId;
        this.claims = Map.copyOf(claims);
    }

    public String getSessionId() {
        return sessionId;
    }

    public Map<String, Object> getClaims() {
        return claims;
    }
}
