package com.yeeyun.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.yeeyun.auth.config.custom.CustomOAuth2TokenCustomizer;
import com.yeeyun.auth.jose.Jwks;
import lombok.SneakyThrows;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Duration;
import java.util.UUID;

/**
 * 认证服务器配置
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationConfig {

    /**
     * 定义 Spring Security 的拦截器链
     */
    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        // 设置 jwt token 个性化
        http.setSharedObject(OAuth2TokenCustomizer.class, new CustomOAuth2TokenCustomizer());
        //
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        return http.formLogin(Customizer.withDefaults()).build();
    }

    /**
     * 创建客户端信息，可以保存在内存和数据库，此处保存在数据库中
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                // 客户端id 需要唯一
                .clientId("messaging-client")
                // 客户端密码
                .clientSecret(("{noop}secret"))
                // 可以基于 basic 的方式和授权服务器进行认证
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                // 授权方式
                .authorizationGrantTypes(authorizationGrantTypes -> {
                    // 授权码
                    authorizationGrantTypes.add(AuthorizationGrantType.AUTHORIZATION_CODE);
                    // 刷新 token
                    authorizationGrantTypes.add(AuthorizationGrantType.REFRESH_TOKEN);
                    // 客户端模式
                    authorizationGrantTypes.add(AuthorizationGrantType.CLIENT_CREDENTIALS);
                })
                // 重定向url
                .redirectUris(redirectUris -> {
                    redirectUris.add("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc");
                    redirectUris.add("http://127.0.0.1:8080/authorized");
                })
                .scope(OidcScopes.OPENID)
                // 客户端申请的作用域，也可以理解这个客户端申请访问用户的哪些信息，比如：获取用户信息，获取用户照片等
                .scope("message.read")
                .scope("message.write")
                .clientSettings(
                        // 是否需要用户确认一下客户端需要获取用户的哪些权限
                        // 比如：客户端需要获取用户的 用户信息、用户照片 但是此处用户可以控制只给客户端授权获取 用户信息。
                        ClientSettings.builder()
                                .requireAuthorizationConsent(true)
                                .build()
                )
                .tokenSettings(TokenSettings.builder()
                        // accessToken 的有效期
                        .accessTokenTimeToLive(Duration.ofDays(1L))
                        // refreshToken 的有效期
                        .refreshTokenTimeToLive(Duration.ofDays(3L))
                        // 是否可重用刷新令牌
                        .reuseRefreshTokens(true)
                        .build())
                .build();
        JdbcRegisteredClientRepository clientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
        clientRepository.save(client);
        return clientRepository;
    }

    /**
     * 保存授权信息，授权服务器给我们颁发来token，那我们肯定需要保存吧，由这个服务来保存
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
                                                           RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 如果是授权码的流程，可能客户端申请了多个权限，
     * 比如：获取用户信息，修改用户信息，
     * 此Service处理的是用户给这个客户端哪些权限，比如只给获取用户信息的权限
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
                                                                         RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * 对JWT进行签名的 加解密密钥
     */
    @Bean
    @SneakyThrows
    public JWKSource<SecurityContext> jwkSource() {
        //
        RSAKey rsaKey = Jwks.generateRsa();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
    }

    /**
     * jwt 解码
     */
    @Bean
    public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        //
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    /**
     * 配置一些断点的路径，比如：获取token、授权端点 等
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder()
                // 发布者的url地址,一般是本系统访问的根路径
                .issuer("http://auth.yeeyun.com:9000")
                .build();
    }

}
