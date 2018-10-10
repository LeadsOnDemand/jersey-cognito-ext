package com.leadsondemand.jersey.security.cognito.service;

import com.anigenero.junit.mockito.MockitoExtension;
import com.leadsondemand.jersey.security.cognito.AuthorizationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthenticationTokenServiceTest {

    @Mock
    private AuthenticationTokenParser mockAuthenticationTokenParser;

    private AuthenticationTokenService authenticationTokenService;

    @BeforeEach
    void setup() {
        this.authenticationTokenService = new AuthenticationTokenService(this.mockAuthenticationTokenParser, 10, 3600L);
    }

    @Test
    void testNoArgConstructor() {
        new AuthenticationTokenService();
    }

    @Test
    void parseToken() {

        when(this.mockAuthenticationTokenParser.parseToken(anyString())).thenReturn(new AuthorizationContext.Builder().build());

        this.authenticationTokenService.parseToken("foobar");

        verify(this.mockAuthenticationTokenParser).parseToken(anyString());

    }

}