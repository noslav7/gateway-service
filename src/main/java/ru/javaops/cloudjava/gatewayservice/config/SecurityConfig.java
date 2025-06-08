package ru.javaops.cloudjava.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.server.DefaultServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.WebSessionServerOAuth2AuthorizedClientRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.XorServerCsrfTokenRequestAttributeHandler;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http,
                                                         ReactiveClientRegistrationRepository clientRegistrationRepository) {
        return http
                .authorizeExchange(exchange ->
                        exchange
                                .pathMatchers("/actuator/**").permitAll()
                                .pathMatchers(HttpMethod.GET, "/v1/menu-items/**").permitAll()
                                .pathMatchers(HttpMethod.GET, "/v1/reviews/menu-item/**").permitAll()
                                .pathMatchers(HttpMethod.GET, "/v1/reviews/{id}").permitAll()
                                .pathMatchers(HttpMethod.GET, "/v1/menu-aggregate/**").permitAll()
                                .pathMatchers(HttpMethod.POST, "/v1/reviews/ratings/**").permitAll()
                                .anyExchange().authenticated())
                .oauth2Login(oauth -> oauth.authorizationRequestResolver(pkceResolver(clientRegistrationRepository)))
                .logout(logout -> logout.logoutSuccessHandler(serverLogoutSuccessHandler(clientRegistrationRepository)))
                .csrf(csrf -> csrf
                        // Используем куки для хранения токенов CSRF. Для того, чтобы Angular
                        // и другие приложения на JS поддерживали такой механизм, необходимо
                        // установить атрибут куки httpOnly = false.
                        // По умолчанию токены CSRF хранятся в веб-сессии.
                        .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
                        // Токены CSRF доступны в качестве атрибута ServerWebExchange, это достигается
                        // за счет наличия в контексте спринга реализации интерфейса ServerCsrfTokenRequestHandler,
                        // по умолчанию используется XorServerCsrfTokenRequestAttributeHandler, который
                        // умеет маскировать токены (c помощью XOR операции) и получать их значение обратно. В данном случае,
                        // конфигурация полностью совпадает с дефолтной и приведена здесь в качестве примера.
                        .csrfTokenRequestHandler(new XorServerCsrfTokenRequestAttributeHandler()))
                .build();
    }

    /**
     * Добавляем в контекст Спринга реализацию [ServerOAuth2AuthorizedClientRepository],
     * которая хранит данные об авторизованных клиентах OAuth 2.0 [OAuth2AuthorizedClient] в сессии.
     * Клиент считается авторизованным, когда пользователь (владелец ресурсов) предоставил
     * ему доступ к защищенным ресурсам. Фактически [OAuth2AuthorizedClient] связывает
     * токен доступа с клиентом и владельцем ресурсов (пользователем).
     */
    @Bean
    public ServerOAuth2AuthorizedClientRepository serverOAuth2AuthorizedClientRepository() {
        return new WebSessionServerOAuth2AuthorizedClientRepository();
    }

    /**
     * Этот бин извлекает из ServerWebExchange атрибут CsrfToken, и
     * подписывается на него. Такое поведение необходимо, так как без подписки
     * реактивные стримы не будут выполняться, и сохранения CSRF токена в
     * CookieServerCsrfTokenRepository не произойдет.
     * На эту тему открыто issue https://github.com/spring-projects/spring-security/issues/5766
     */
    @Bean
    public WebFilter csrfWebFilter() {
        return (exchange, chain) -> {
            exchange.getResponse().beforeCommit(() -> Mono.defer(() -> {
                Mono<CsrfToken> csrfToken = exchange.getAttribute(CsrfToken.class.getName());
                return csrfToken != null ? csrfToken.then() : Mono.empty();
            }));
            return chain.filter(exchange);
        };
    }


    /**
     * При нажатии на кнопку Logout на сайте, пользователь выходит из своей учетной записи на
     * самом сайте, однако на сервере авторизации (в нашем случае Keycloak) он по умолчанию
     * остается авторизованным. Согласно лучшим практикам, нам необходимо разлогинить
     * пользователя на сервере авторизации. Для этого мы создаем реализацию интерфейса
     * [ServerLogoutSuccessHandler], которая отвечает за этот процесс - [OidcClientInitiatedServerLogoutSuccessHandler].
     * Реализации необходимо знать информацию о клиенте OAuth 2.0, для этого в конструкторе
     * мы передаем репозиторий [ReactiveClientRegistrationRepository], хранящий данные сведения.
     * По умолчанию в Spring данные сведения хранятся в памяти приложения.
     */
    private ServerLogoutSuccessHandler serverLogoutSuccessHandler(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        var logoutSuccessHandler = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
        logoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}");
        return logoutSuccessHandler;
    }

    /**
     * Резолвер запросов на авторизацию в сервер авторизации.
     * Позволяет кастомизировать запрос на авторизацию. В данном случае мы добавляем PKCE защиту:
     * на стороне клиента будет сформирован code_verifier, на основе
     * code_verifier будет подготовлен code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier))).
     * Далее в запрос на авторизацию будут добавлены параметры: code_challenge и code_challenge_method.
     */
    private ServerOAuth2AuthorizationRequestResolver pkceResolver(ReactiveClientRegistrationRepository clientRegistrationRepository) {
        var resolver = new DefaultServerOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return resolver;
    }
}