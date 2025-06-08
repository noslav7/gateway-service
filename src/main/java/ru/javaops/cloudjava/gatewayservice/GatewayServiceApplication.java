package ru.javaops.cloudjava.gatewayservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration;
import reactor.core.publisher.Hooks;

@SpringBootApplication(exclude = ReactiveUserDetailsServiceAutoConfiguration.class)
public class GatewayServiceApplication {

    public static void main(String[] args) {
        Hooks.enableAutomaticContextPropagation();
        SpringApplication.run(GatewayServiceApplication.class, args);
    }
}
