package ru.javaops.cloudjava.gatewayservice.filters;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
@Slf4j
public class TokenToHeaderFilter implements GlobalFilter, Ordered {
    private static final String USERNAME_HEADER = "X-User-Name";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
                .filter(p -> p instanceof Authentication).cast(Authentication.class)
                .map(authentication -> withUserNameHeader(exchange, authentication.getName()))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    private ServerWebExchange withUserNameHeader(ServerWebExchange exchange, String username) {
        return exchange.mutate()
                .request(r -> r.headers(headers -> headers.set(USERNAME_HEADER, username))).build();
    }

    @Override
    public int getOrder() {
        return Ordered.LOWEST_PRECEDENCE;
    }
}