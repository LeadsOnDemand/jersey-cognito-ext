package com.leadsondemand.jersey.security.cognito;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationContextTest {

    @Test
    void testBuilder() {

        final String tokenId = "291230935721";
        final Set<String> authorities = new HashSet<>(Arrays.asList("insert", "update"));

        final AuthorizationContext.Builder builder = new AuthorizationContext.Builder();
        builder.withAppId(tokenId)
                .withRoles(authorities);

        final AuthorizationContext result = builder.build();

        assertThat(result).isNotNull();
        assertThat(result.getAppId()).isEqualTo(tokenId);
        assertThat(result.getRoles()).isEqualTo(authorities);

    }

}