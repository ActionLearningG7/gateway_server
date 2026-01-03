package com.medibridge.apigateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
public class GatewayConfig {

    @Bean
    protected SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) throws Exception {

        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(auth -> auth
                        .anyExchange().permitAll())
                .cors(cors -> {

                    cors.configurationSource(corsConfiguration());
                })
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable);

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfiguration() {
        CorsConfiguration corsConfig = new CorsConfiguration();
        corsConfig.addAllowedOriginPattern("*");
        corsConfig.setAllowCredentials(true);

        List<String> exposedHeaders = List.of("Authorization", "content-type", "Access-Control-Allow-Origin",
                "Access-Control-Allow-Credentials");
        corsConfig.setExposedHeaders(exposedHeaders);

        List<String> allowedMethods = List.of("GET", "POST", "PUT", "DELETE", "OPTIONS");
        corsConfig.setAllowedMethods(allowedMethods);

        List<String> allowOrigins = List.of(
                "http://localhost:3000",
                "http://localhost:3001",
                "https://medibridge-frontend.onrender.com");
        corsConfig.setAllowedOrigins(allowOrigins);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", corsConfig);

        return source;
    }

}
