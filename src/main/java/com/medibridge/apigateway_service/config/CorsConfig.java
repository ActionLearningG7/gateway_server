package com.medibridge.apigateway_service.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

/**
 * CORS configuration for API Gateway
 * Centralizes cross-origin resource sharing policies
 */
@Configuration
public class CorsConfig {

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();

        // Allow specified origins only (production: configure from environment)
        configuration.setAllowedOrigins(Arrays.asList(
                "http://localhost:3000",      // React frontend (dev)
                "http://localhost:3001",
                "http://127.0.0.1:3000"
        ));

        // Allow credentials in CORS requests
        configuration.setAllowCredentials(true);

        // Allow HTTP methods
        configuration.setAllowedMethods(Arrays.asList(
                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"
        ));

        // Allow headers
        configuration.setAllowedHeaders(Arrays.asList(
                "Authorization",
                "Content-Type",
                "X-Correlation-Id",
                "X-Requested-With",
                "Accept",
                "Origin"
        ));

        // Expose headers to client
        configuration.setExposedHeaders(Arrays.asList(
                "Authorization",
                "X-Correlation-Id",
                "Content-Type"
        ));

        // Max age of CORS preflight response
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);

        return source;
    }
}

