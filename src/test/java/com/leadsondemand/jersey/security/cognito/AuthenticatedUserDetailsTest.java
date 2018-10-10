package com.leadsondemand.jersey.security.cognito;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

class AuthenticatedUserDetailsTest {

    @Test
    void testAuthenticatedUserDetails() {

        final Set<String> roles = new HashSet<>(Arrays.asList("foo", "bar"));
        final String username = "nick.fury";

        final AuthenticatedUserDetails authenticatedUserDetails = new AuthenticatedUserDetails(roles, username);

        assertThat(authenticatedUserDetails.getRoles()).isEqualTo(roles);
        assertThat(authenticatedUserDetails.getName()).isEqualTo(username);

    }

}