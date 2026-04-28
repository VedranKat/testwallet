package com.example.qrgen.web;

import com.example.qrgen.config.DemoProperties;
import com.example.qrgen.oid4vp.WalletLoginService;
import com.example.qrgen.oid4vp.WalletLoginSession;
import com.example.qrgen.security.PidAuthentication;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

@Controller
public class WebController {

    private final DemoProperties properties;
    private final WalletLoginService walletLoginService;

    public WebController(DemoProperties properties, WalletLoginService walletLoginService) {
        this.properties = properties;
        this.walletLoginService = walletLoginService;
    }

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/")
    String home(Model model, Authentication authentication) {
        model.addAttribute("properties", properties);
        model.addAttribute("authentication", authentication);
        return "dashboard";
    }

    @GetMapping("/certificates")
    String certificates(Model model) {
        model.addAttribute("properties", properties);
        return "certificates";
    }

    @GetMapping("/wallet-login")
    String walletLogin(Model model) {
        model.addAttribute("properties", properties);
        return "wallet-login-start";
    }

    @GetMapping("/wallet-login/{id}")
    String walletLoginDetails(@PathVariable String id, Model model) {
        WalletLoginSession session = walletLoginService.find(id).orElseThrow(RequestNotFoundException::new);
        model.addAttribute("walletSession", session);
        model.addAttribute("decodedPayload", walletLoginService.decodedJwtPayload(session.signedRequestObject()));
        return "wallet-login-details";
    }

    @GetMapping("/profile")
    String profile(Model model, Authentication authentication) {
        model.addAttribute("authentication", authentication);
        if (authentication instanceof PidAuthentication pidAuthentication) {
            model.addAttribute("pidClaims", pidAuthentication.getClaims());
        }
        return "profile";
    }

    static ResponseEntity<byte[]> pemDownload(byte[] body, String filename) {
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(filename).build().toString())
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(body);
    }
}
