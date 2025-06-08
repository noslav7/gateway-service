package ru.javaops.cloudjava.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;
import reactor.core.publisher.Flux;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .authorizeExchange(exchange ->
                        exchange
                                .pathMatchers("/actuator/**").permitAll()
                                // matchers for Menu Service
                                .pathMatchers(HttpMethod.GET, "/v1/menu-items/**").permitAll()
                                .pathMatchers(HttpMethod.POST, "/v1/menu-items/menu-info").permitAll()
                                .pathMatchers(HttpMethod.POST, "/v1/menu-items/**").hasRole("ADMIN")
                                .pathMatchers(HttpMethod.DELETE, "/v1/menu-items/**").hasRole("ADMIN")
                                .pathMatchers(HttpMethod.PATCH, "/v1/menu-items/**").hasRole("ADMIN")
                                // matchers for Orders Service
                                .pathMatchers("/v1/menu-orders/**").hasRole("USER")
                                // matchers for Review Service
                                .pathMatchers(HttpMethod.POST, "/v1/reviews/ratings").permitAll()
                                .pathMatchers(HttpMethod.POST, "/v1/reviews/**").hasRole("USER")
                                .pathMatchers(HttpMethod.GET, "/v1/reviews/my/**").hasRole("USER")
                                .pathMatchers(HttpMethod.GET, "/v1/reviews/menu-item/**").permitAll()
                                .pathMatchers(HttpMethod.GET, "/v1/reviews/{id}").permitAll()
                                // matchers for Menu Aggregate Service
                                .pathMatchers(HttpMethod.GET, "/v1/menu-aggregate/**").permitAll()
                                .anyExchange().authenticated())
                //  настраиваем сервера ресурсов c JWT-токенами
                .oauth2ResourceServer(customizer -> customizer.jwt(Customizer.withDefaults()))
                // отключаем сессии
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                // отключаем защиту от CSRF, так как не взаимодействуем с браузером
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .build();
    }

    /**
     * Конвертер, который используется для преобразования JWT в Mono<AbstractAuthenticationToken>.
     */
    @Bean
    public ReactiveJwtAuthenticationConverter authenticationConverter(Converter<Jwt, Flux<GrantedAuthority>> authoritiesConverter) {
        final var authenticationConverter = new ReactiveJwtAuthenticationConverter();
        authenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        authenticationConverter.setPrincipalClaimName(StandardClaimNames.PREFERRED_USERNAME);
        return authenticationConverter;
    }
}