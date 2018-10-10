package com.anigenero.jersey.security.cognito.service;

import com.anigenero.cdi.configuration.Configuration;
import com.anigenero.jersey.security.cognito.AuthorizationContext;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;
import java.time.ZonedDateTime;

@ApplicationScoped
public class AuthenticationTokenService {

    @Inject
    private AuthenticationTokenParser tokenParser;

    @Inject
    @Configuration("authentication.jwt.refreshLimit")
    private Integer refreshLimit;

    @Inject
    @Configuration("authentication.jwt.validFor")
    private Long validFor;

    @SuppressWarnings("WeakerAccess")
    public AuthenticationTokenService() {
    }

    @SuppressWarnings("WeakerAccess")
    public AuthenticationTokenService(AuthenticationTokenParser tokenParser, Integer refreshLimit, Long validFor) {
        this.tokenParser = tokenParser;
        this.refreshLimit = refreshLimit;
        this.validFor = validFor;
    }

    /**
     * Parse and validate the token.
     *
     * @param token {@link String}
     * @return {@link AuthorizationContext}
     */
    public AuthorizationContext parseToken(String token) {
        return tokenParser.parseToken(token);
    }

    /**
     * Calculate the expiration date for a token.
     *
     * @param issuedDate {@link ZonedDateTime}
     * @return {@link ZonedDateTime}
     */
    private ZonedDateTime calculateExpirationDate(ZonedDateTime issuedDate) {
        return issuedDate.plusSeconds(validFor);
    }

}
