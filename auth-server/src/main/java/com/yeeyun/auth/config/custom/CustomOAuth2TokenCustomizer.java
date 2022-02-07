package com.yeeyun.auth.config.custom;

import org.springframework.security.oauth2.server.authorization.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenCustomizer;

/**
 * 个性化 JWT token
 */
public class CustomOAuth2TokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        // 添加一个自定义头
        context.getHeaders().header("client-id", context.getRegisteredClient().getClientId());
    }
}
