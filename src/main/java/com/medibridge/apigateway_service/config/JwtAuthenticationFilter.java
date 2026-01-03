package com.medibridge.apigateway_service.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * JWT token validation filter for API Gateway
 * Validates JWT tokens before routing to backend services
 */
@Component
@Slf4j
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/api/v1/users/auth/signup",
            "/api/v1/users/auth/signin",
            "/api/v1/users/auth/refresh-token",
            "/api/v1/users/register",
            "/api/v1/users/login",
            "/api/v1/users/refresh",
            "/actuator/health",
            "/actuator/info"
    );

    public JwtAuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            String path = request.getURI().getPath();

            // Skip authentication for public endpoints
            if (isPublicEndpoint(path)) {
                log.debug("Public endpoint accessed: {}", path);
                return chain.filter(exchange);
            }

            // Extract and validate JWT token
            String token = extractToken(request);
            log.debug("Token extracted for path: {} - Token present: {}", path, token != null);

            if (token == null) {
                log.warn("No JWT token found in Authorization header for path: {}", path);
                return handleUnauthorized(exchange, "Missing JWT token. Please provide Authorization header with Bearer token");
            }

            if (!validateToken(token)) {
                log.warn("JWT token validation failed for path: {}", path);
                return handleUnauthorized(exchange, "Invalid JWT token. Please provide a valid token");
            }

            // Extract user information from token and add to request headers
            try {
                Claims claims = extractClaims(token);
                String userId = claims.getSubject();
                String userRole = (String) claims.get("role");

                log.info("JWT validated successfully - User: {}, Role: {}, Path: {}", userId, userRole, path);

                // Add user info to request headers for downstream services
                ServerHttpRequest modifiedRequest = request.mutate()
                        .header("X-User-Id", userId)
                        .header("X-User-Role", userRole)
                        .header("X-Correlation-Id", extractOrGenerateCorrelationId(request))
                        .build();

                ServerWebExchange modifiedExchange = exchange.mutate()
                        .request(modifiedRequest)
                        .build();

                log.debug("JWT validated for user: {} with role: {}", userId, userRole);
                return chain.filter(modifiedExchange);
            } catch (Exception ex) {
                log.error("JWT validation error: {}", ex.getMessage(), ex);
                return handleUnauthorized(exchange, "Invalid JWT token: " + ex.getMessage());
            }
        };
    }

    private boolean isPublicEndpoint(String path) {
        return PUBLIC_ENDPOINTS.stream().anyMatch(path::startsWith);
    }

    private String extractToken(ServerHttpRequest request) {
        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        return null;
    }

    private boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                    .build()
                    .parseClaimsJws(token);
            log.debug("Token validation successful");
            return true;
        } catch (io.jsonwebtoken.ExpiredJwtException ex) {
            log.warn("Token has expired: {}", ex.getMessage());
            return false;
        } catch (io.jsonwebtoken.MalformedJwtException ex) {
            log.warn("Malformed JWT token: {}", ex.getMessage());
            return false;
        } catch (io.jsonwebtoken.SignatureException ex) {
            log.warn("Invalid JWT signature: {}", ex.getMessage());
            return false;
        } catch (Exception ex) {
            log.warn("Token validation failed: {} - {}", ex.getClass().getSimpleName(), ex.getMessage());
            return false;
        }
    }

    private Claims extractClaims(String token) {
        return Jwts.parser()
                .setSigningKey(Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8)))
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private String extractOrGenerateCorrelationId(ServerHttpRequest request) {
        String correlationId = request.getHeaders().getFirst("X-Correlation-Id");
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = java.util.UUID.randomUUID().toString();
        }
        return correlationId;
    }

    private Mono<Void> handleUnauthorized(ServerWebExchange exchange, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(HttpStatus.UNAUTHORIZED);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String errorJson = String.format(
                "{\"status\":401,\"error\":\"UNAUTHORIZED\",\"message\":\"%s\"}",
                message
        );

        byte[] bytes = errorJson.getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);

        return response.writeWith(Mono.just(buffer));
    }

    public static class Config {
        // Configuration class for filter
    }
}

