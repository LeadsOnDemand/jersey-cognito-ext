package com.anigenero.jersey.security.cognito;

import java.security.Principal;
import java.util.Collections;
import java.util.Set;

class AuthenticatedUserDetails implements Principal {

    private final Set<String> roles;
    private final String username;

    AuthenticatedUserDetails(Set<String> roles, String username) {
        this.roles = Collections.unmodifiableSet(roles);
        this.username = username;
    }

    public Set<String> getRoles() {
        return roles;
    }

    @Override
    public String getName() {
        return username;
    }

}
