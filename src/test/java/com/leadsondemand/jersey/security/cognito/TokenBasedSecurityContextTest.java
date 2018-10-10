package com.leadsondemand.jersey.security.cognito;

import org.junit.jupiter.api.Test;

import java.time.ZonedDateTime;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TokenBasedSecurityContextTest {

    @Test
    void testTokenBasedSecurityContext() {

        final String username = "nick.fury";
        final Set<String> roles = new HashSet<>(Arrays.asList("insert", "update"));

        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(roles, username);
        final AuthorizationContext authorizationContext = new AuthorizationContext("foobar", roles);

        final TokenBasedSecurityContext context = new TokenBasedSecurityContext(userDetails, authorizationContext, true);

        assertThat(context.getUserPrincipal()).isEqualTo(userDetails);
        assertThat(context.isUserInRole("insert")).isTrue();
        assertThat(context.isUserInRole("update")).isTrue();
        assertThat(context.isUserInRole("delete")).isFalse();
        assertThat(context.isSecure()).isTrue();
        assertThat(context.getAuthenticationScheme()).isEqualTo("Bearer");
        assertThat(context.getAuthorizationContext()).isEqualTo(authorizationContext);

    }

    @Test
    void testTokenBasedSecurityContextWithNull() {

        final TokenBasedSecurityContext context = new TokenBasedSecurityContext(null, null, true);

        assertThat(context.isUserInRole("delete")).isFalse();

    }

}