package com.medibridge.apigateway_service.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Bucket4j;
import io.github.bucket4j.Refill;
import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate limiting filter using Bucket4j
 * Provides request throttling per user/API key
 */
@Component
@Slf4j
public class RateLimitingFilter extends AbstractGatewayFilterFactory<RateLimitingFilter.Config> {

    private final ConcurrentHashMap<String, Bucket> cache = new ConcurrentHashMap<>();

    public RateLimitingFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            String userId = exchange.getRequest().getHeaders().getFirst("X-User-Id");
            String identifier = (userId != null)
                    ? userId
                    : exchange.getRequest().getRemoteAddress()
                    .getAddress()
                    .getHostAddress();

            Bucket bucket = cache.computeIfAbsent(identifier, k -> createNewBucket(config));

            if (bucket.tryConsume(1)) {
                log.debug("Rate limit check passed for identifier: {}", identifier);
                return chain.filter(exchange);
            }

            log.warn("Rate limit exceeded for identifier: {}", identifier);

            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.TOO_MANY_REQUESTS);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            response.getHeaders().add("X-RateLimit-Retry-After-Seconds", "60");

            String body = """
                {
                  "status": 429,
                  "error": "RATE_LIMIT_EXCEEDED",
                  "message": "Too many requests"
                }
                """;

            DataBuffer buffer = response.bufferFactory()
                    .wrap(body.getBytes(StandardCharsets.UTF_8));

            return response.writeWith(Mono.just(buffer));
        };
    }

    private Bucket createNewBucket(Config config) {
        Bandwidth limit = Bandwidth.classic(config.requestsPerMinute, Refill.intervally(config.requestsPerMinute, Duration.ofMinutes(1)));
        return Bucket4j.builder()
                .addLimit(limit)
                .build();
    }

    public static class Config {
        /**
         * Number of requests allowed per minute
         */
        public int requestsPerMinute = 1000; // Default: 1000 requests/minute
    }
}

