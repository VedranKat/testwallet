package com.example.qrgen.web;

import com.example.qrgen.oid4vp.DirectPostRequest;
import com.example.qrgen.oid4vp.WalletLoginService;
import com.example.qrgen.oid4vp.WalletLoginSession;
import com.example.qrgen.oid4vp.WalletLoginStatus;
import com.example.qrgen.requests.QrCodeService;
import com.example.qrgen.security.PidAuthentication;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.stereotype.Controller;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.util.Map;

@Controller
public class Oid4vpController {

    private final WalletLoginService walletLoginService;
    private final QrCodeService qrCodeService;
    private final ObjectMapper objectMapper;

    public Oid4vpController(WalletLoginService walletLoginService, QrCodeService qrCodeService, ObjectMapper objectMapper) {
        this.walletLoginService = walletLoginService;
        this.qrCodeService = qrCodeService;
        this.objectMapper = objectMapper;
    }

    @PostMapping("/oid4vp/sessions")
    String createSession(@RequestParam(defaultValue = "true") boolean includeNationality) {
        WalletLoginSession session = walletLoginService.createSession(includeNationality);
        return "redirect:/wallet-login/" + session.id();
    }

    @GetMapping(value = "/oid4vp/sessions/{id}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    WalletLoginSession session(@PathVariable String id) {
        return walletLoginService.find(id).orElseThrow(RequestNotFoundException::new);
    }

    @GetMapping(value = "/oid4vp/sessions/{id}/qr", produces = MediaType.IMAGE_PNG_VALUE)
    @ResponseBody
    byte[] qr(@PathVariable String id) {
        WalletLoginSession session = walletLoginService.find(id).orElseThrow(RequestNotFoundException::new);
        return qrCodeService.png(session.qrUri(), 640);
    }

    @GetMapping(value = "/oid4vp/requests/{id}/object.jwt", produces = "application/oauth-authz-req+jwt")
    @ResponseBody
    String objectJwt(@PathVariable String id) {
        return walletLoginService.find(id).orElseThrow(RequestNotFoundException::new).signedRequestObject();
    }

    @GetMapping(value = "/oid4vp/requests/{id}/payload.json", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    Map<String, Object> payload(@PathVariable String id) {
        return walletLoginService.find(id).orElseThrow(RequestNotFoundException::new).payload();
    }

    @GetMapping(value = "/oid4vp/sessions/{id}/status", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    Map<String, Object> status(@PathVariable String id, HttpServletRequest request) {
        WalletLoginSession session = walletLoginService.find(id).orElseThrow(RequestNotFoundException::new);
        if (session.status() == WalletLoginStatus.VERIFIED) {
            PidAuthentication authentication = new PidAuthentication(session.id(), session.verifiedClaims());
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.getSession(true).setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextHolder.getContext());
        }
        return Map.of("id", session.id(), "status", session.status(), "failureReason", session.failureReason() == null ? "" : session.failureReason());
    }

    @PostMapping(value = "/oid4vp/direct_post", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    @ResponseBody
    Map<String, Object> directPostForm(@RequestParam MultiValueMap<String, String> form) {
        WalletLoginSession session = walletLoginService.verifyDirectPost(new DirectPostRequest(
                form.getFirst("state"),
                form.getFirst("vp_token"),
                parsePresentationSubmission(form.getFirst("presentation_submission"))));
        return response(session);
    }

    @PostMapping(value = "/oid4vp/direct_post", consumes = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    Map<String, Object> directPostJson(@RequestBody DirectPostRequest post) {
        WalletLoginSession session = walletLoginService.verifyDirectPost(post);
        return response(session);
    }

    private Map<String, Object> response(WalletLoginSession session) {
        return Map.of("id", session.id(), "status", session.status(), "failureReason", session.failureReason() == null ? "" : session.failureReason());
    }

    private Map<String, Object> parsePresentationSubmission(String value) {
        if (value == null || value.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(value, new TypeReference<>() {
            });
        } catch (Exception ex) {
            return Map.of("raw", value);
        }
    }
}
