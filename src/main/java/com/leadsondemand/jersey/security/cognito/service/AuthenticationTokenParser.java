package com.leadsondemand.jersey.security.cognito.service;

import com.anigenero.cdi.configuration.Configuration;
import com.auth0.jwk.Jwk;
import com.auth0.jwk.JwkProvider;
import com.auth0.jwk.JwkProviderBuilder;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.leadsondemand.jersey.security.cognito.AuthorizationContext;
import com.leadsondemand.jersey.security.cognito.exception.InvalidAuthenticationTokenException;
import com.leadsondemand.jersey.security.cognito.util.JWKUtil;

import javax.inject.Inject;
import javax.validation.constraints.NotNull;
import java.security.interfaces.RSAPublicKey;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

public class AuthenticationTokenParser {

    @Inject
    @Configuration("aws.cognito.region")
    private String awsRegion;

    @Inject
    @Configuration("aws.cognito.userPoolId")
    private String cognitoUserPoolId;

    @SuppressWarnings({"WeakerAccess", "unused"})
    public AuthenticationTokenParser() {
    }

    /**
     * Parse a JWT token.
     *
     * @param token {@link String}
     * @return {@link AuthorizationContext}
     */
    public AuthorizationContext parseToken(final String token) {

        try {

            final DecodedJWT jwt = JWT.decode(token);
            final JwkProvider provider = new JwkProviderBuilder(JWKUtil.getJWKUrl(this.awsRegion, this.cognitoUserPoolId))
                    .cached(10, 24, TimeUnit.HOURS)
                    .build();

            Jwk jwk = provider.get(jwt.getKeyId());

            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) jwk.getPublicKey(), null);
            JWTVerifier verifier = JWT.require(algorithm)
                    .withIssuer(JWKUtil.getIssuer(this.cognitoUserPoolId))
                    .build();

            verifier.verify(token);

            return new AuthorizationContext.Builder()
                    .withAppId(extractTokenIdFromToken(jwt))
                    .withRoles(extractRolesFromClaims(jwt))
                    .build();

        } catch (InvalidClaimException e) {
            throw new InvalidAuthenticationTokenException("Invalid claim encountered", e);
        } catch (Exception e) {
            throw new InvalidAuthenticationTokenException("Invalid authentication token", e);
        }

    }

    /**
     * Extract the token identifier from the token claims.
     *
     * @param jwt {@link DecodedJWT}
     * @return Identifier of the JWT token
     */
    private String extractTokenIdFromToken(@NotNull DecodedJWT jwt) {
        return jwt.getHeaderClaim("aud").asString();
    }

    /**
     * Extract the user authorities from the token claims.
     *
     * @param jwt {@link DecodedJWT}
     * @return User authorities from the JWT token
     */
    @SuppressWarnings("unchecked")
    private Set<String> extractRolesFromClaims(@NotNull DecodedJWT jwt) {
        List<String> rolesAsString = Arrays.asList(jwt.getHeaderClaim("cognito:roles").asString().split(","));
        return rolesAsString.stream().map(String::valueOf).collect(Collectors.toSet());
    }

}
