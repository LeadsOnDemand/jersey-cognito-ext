package com.anigenero.jersey.security.cognito;

import javax.ws.rs.core.SecurityContext;
import java.security.Principal;

class TokenBasedSecurityContext implements SecurityContext {

    private final AuthenticatedUserDetails authenticatedUserDetails;
    private final AuthorizationContext authenticationTokenDetails;
    private final boolean secure;

    TokenBasedSecurityContext(AuthenticatedUserDetails authenticatedUserDetails,
                              AuthorizationContext authenticationTokenDetails,
                              boolean secure) {

        this.authenticatedUserDetails = authenticatedUserDetails;
        this.authenticationTokenDetails = authenticationTokenDetails;
        this.secure = secure;

    }

    @Override
    public Principal getUserPrincipal() {
        return authenticatedUserDetails;
    }

    @Override
    public boolean isUserInRole(String role) {
        return authenticatedUserDetails != null && authenticatedUserDetails.getRoles().contains(role);
    }

    @Override
    public boolean isSecure() {
        return secure;
    }

    @Override
    public String getAuthenticationScheme() {
        return "Bearer";
    }

    public AuthorizationContext getAuthorizationContext() {
        return authenticationTokenDetails;
    }

}
