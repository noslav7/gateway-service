package ru.javaops.cloudjava.gatewayservice.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Flux;

/**
 * Конвертер, который извлекает из JWT роли и формирует из них Flux<GrantedAuthority>.
 */
@Component
public class KeycloakClientAuthoritiesConverter implements Converter<Jwt, Flux<GrantedAuthority>> {

    @Override
    public Flux<GrantedAuthority> convert(Jwt source) {
        var roles = source.getClaimAsStringList("roles");
        return Flux.fromStream(roles.stream())
                .map("ROLE_%s"::formatted)
                .map(SimpleGrantedAuthority::new)
                .map(GrantedAuthority.class::cast);
    }

}