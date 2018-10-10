package com.leadsondemand.jersey.security.cognito;

import com.leadsondemand.jersey.security.cognito.service.AuthenticationTokenService;

import javax.annotation.Priority;
import javax.inject.Inject;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.AUTHENTICATION)
public class AuthenticationFilter implements ContainerRequestFilter {

    @Inject
    private AuthenticationTokenService authenticationTokenService;

    @SuppressWarnings("WeakerAccess")
    public AuthenticationFilter() {
    }

    @SuppressWarnings("WeakerAccess")
    public AuthenticationFilter(AuthenticationTokenService authenticationTokenService) {
        this.authenticationTokenService = authenticationTokenService;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {

        String authorizationHeader = requestContext.getHeaderString(HttpHeaders.AUTHORIZATION);
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            handleTokenBasedAuthentication(authorizationHeader.substring(7), requestContext);
        } else {
            requestContext.setSecurityContext(new TokenBasedSecurityContext(null, null, requestContext.getSecurityContext().isSecure()));
        }

    }

    /**
     * Parse the authentication token and set it to the request context
     *
     * @param authenticationToken {@link String}
     * @param requestContext      {@link ContainerRequestContext}
     */
    private void handleTokenBasedAuthentication(String authenticationToken, ContainerRequestContext requestContext) {

        AuthorizationContext authorizationContext = authenticationTokenService.parseToken(authenticationToken);
        AuthenticatedUserDetails authenticatedUserDetails = new AuthenticatedUserDetails(authorizationContext.getRoles(), null);

        boolean isSecure = requestContext.getSecurityContext().isSecure();
        requestContext.setSecurityContext(new TokenBasedSecurityContext(authenticatedUserDetails,
                authorizationContext, isSecure));

    }

}
