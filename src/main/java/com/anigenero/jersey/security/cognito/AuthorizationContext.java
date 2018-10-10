package com.anigenero.jersey.security.cognito;

import java.util.Set;

public final class AuthorizationContext {

    private final String appId;

    private final Set<String> roles;

    AuthorizationContext(String appId, Set<String> roles) {
        this.appId = appId;
        this.roles = roles;
    }

    public String getAppId() {
        return appId;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public static final class Builder {

        private String appId;

        private Set<String> roles;

        public Builder withAppId(String appId) {
            this.appId = appId;
            return this;
        }

        public Builder withRoles(Set<String> roles) {
            this.roles = roles;
            return this;
        }

        public AuthorizationContext build() {
            return new AuthorizationContext(this.appId, this.roles);
        }

    }

}
