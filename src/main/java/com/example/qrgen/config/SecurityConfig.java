package com.example.qrgen.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.ignoringRequestMatchers(
                        "/oid4vp/direct_post",
                        "/oid4vp/sessions",
                        "/wallet/direct_post/*",
                        "/par",
                        "/authorize",
                        "/token",
                        "/credential"))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/",
                                "/login",
                                "/css/**",
                                "/.well-known/openid-credential-issuer",
                                "/.well-known/oauth-authorization-server",
                                "/credential-offer",
                                "/issuer-offer",
                                "/issuer-offer/qr",
                                "/par",
                                "/authorize",
                                "/token",
                                "/credential",
                                "/status-list.jwt",
                                "/certs/**",
                                "/oid4vp/direct_post",
                                "/oid4vp/requests/*/payload.json",
                                "/oid4vp/requests/*/object.jwt",
                                "/oid4vp/sessions",
                                "/oid4vp/sessions/*",
                                "/oid4vp/sessions/*/qr",
                                "/oid4vp/sessions/*/status",
                                "/wallet/request.jwt/*",
                                "/wallet/direct_post/*",
                                "/wallet-login",
                                "/wallet-login/*"
                        ).permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form
                        .loginPage("/login")
                        .defaultSuccessUrl("/", true)
                        .permitAll())
                .logout(logout -> logout.logoutSuccessUrl("/login?logout"));
        return http.build();
    }

    @Bean
    UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
        return new InMemoryUserDetailsManager(User.withUsername("demo")
                .password(passwordEncoder.encode("demo"))
                .roles("ADMIN")
                .build());
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
