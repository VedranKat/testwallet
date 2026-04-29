package com.example.qrgen.web;

import com.example.qrgen.oid4vci.Oid4vciIssuerService;
import com.example.qrgen.oid4vci.ParRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.view.RedirectView;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

@Controller
public class Oid4vciController {

    private final Oid4vciIssuerService issuerService;

    public Oid4vciController(Oid4vciIssuerService issuerService) {
        this.issuerService = issuerService;
    }

    @GetMapping(value = "/.well-known/openid-credential-issuer", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    Map<String, Object> credentialIssuerMetadata() {
        return issuerService.credentialIssuerMetadata();
    }

    @GetMapping(value = "/.well-known/oauth-authorization-server", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    Map<String, Object> authorizationServerMetadata() {
        return issuerService.authorizationServerMetadata();
    }

    @PostMapping(value = "/par", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    ResponseEntity<Map<String, Object>> par(@RequestParam MultiValueMap<String, String> form) {
        try {
            ParRequest request = issuerService.createPar(
                    form.getFirst("client_id"),
                    form.getFirst("response_type"),
                    form.getFirst("redirect_uri"),
                    form.getFirst("scope"),
                    form.getFirst("state"),
                    form.getFirst("code_challenge"),
                    form.getFirst("code_challenge_method"));
            return ResponseEntity.ok(Map.of("expires_in", 3600, "request_uri", request.requestUri()));
        } catch (Exception ex) {
            return oauthError(ex);
        }
    }

    @GetMapping("/authorize")
    String authorize(@RequestParam("client_id") String clientId, @RequestParam("request_uri") String requestUri, Model model) {
        ParRequest request = issuerService.findPar(requestUri).orElseThrow(RequestNotFoundException::new);
        model.addAttribute("clientId", clientId);
        model.addAttribute("requestUri", requestUri);
        model.addAttribute("scope", request.scope());
        model.addAttribute("state", request.state());
        return "issuer-authorize";
    }

    @PostMapping("/authorize")
    RedirectView approve(@RequestParam("client_id") String clientId, @RequestParam("request_uri") String requestUri) {
        ParRequest request = issuerService.findPar(requestUri).orElseThrow(RequestNotFoundException::new);
        String code = issuerService.approve(requestUri, clientId);
        String redirect = request.redirectUri()
                + "?code=" + encode(code)
                + "&state=" + encode(request.state())
                + "&iss=" + encode(issuerService.authorizationServerMetadata().get("issuer").toString())
                + "&client_id=" + encode(clientId);
        return new RedirectView(redirect);
    }

    @PostMapping(value = "/token", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    ResponseEntity<Map<String, Object>> token(@RequestParam MultiValueMap<String, String> form) {
        try {
            return ResponseEntity.ok(issuerService.exchangeToken(
                    form.getFirst("grant_type"),
                    form.getFirst("code"),
                    form.getFirst("code_verifier"),
                    form.getFirst("redirect_uri"),
                    form.getFirst("client_id")));
        } catch (Exception ex) {
            return oauthError(ex);
        }
    }

    @PostMapping(value = "/credential", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    ResponseEntity<Map<String, Object>> credential(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
                                                   @RequestBody Map<String, Object> request) {
        try {
            return ResponseEntity.ok(issuerService.issueCredential(authorizationHeader, request));
        } catch (Exception ex) {
            return oauthError(ex);
        }
    }

    @GetMapping(value = "/status-list.jwt", produces = "application/statuslist+jwt")
    @ResponseBody
    String statusList() {
        return issuerService.statusListJwt();
    }

    private ResponseEntity<Map<String, Object>> oauthError(Exception ex) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", "invalid_request");
        body.put("error_description", ex.getMessage());
        return ResponseEntity.badRequest().body(body);
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
