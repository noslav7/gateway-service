package ru.javaops.cloudjava.gatewayservice.config;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

@Configuration
public class RequestRateLimiterConfig {

    @Bean
    public KeyResolver keyResolver() {
        return exchange -> Mono.just("anyUser");
    }
}