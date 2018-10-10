package com.anigenero.jersey.security.cognito;

import com.anigenero.jersey.security.cognito.exception.AccessDeniedException;

import javax.annotation.Priority;
import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.Priorities;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import javax.ws.rs.ext.Provider;
import java.lang.reflect.Method;

@Provider
@Priority(Priorities.AUTHORIZATION)
public class AuthorizationFilter implements ContainerRequestFilter {

    @Context
    private ResourceInfo resourceInfo;

    public AuthorizationFilter() {
    }

    public AuthorizationFilter(@Context ResourceInfo resourceInfo) {
        this.resourceInfo = resourceInfo;
    }

    @Override
    public void filter(final ContainerRequestContext requestContext) {

        Method method = resourceInfo.getResourceMethod();

        // @DenyAll on the method takes precedence over @RolesAllowed and @PermitAll
        if (method.isAnnotationPresent(DenyAll.class)) {
            throw new AccessDeniedException("Access denied");
        }

        // @PermitAll on the method takes precedence over @RolesAllowed on the class
        if (method.isAnnotationPresent(PermitAll.class)) {
            return;
        }

        // @RolesAllowed on the method takes precedence over @PermitAll
        RolesAllowed rolesAllowed = method.getAnnotation(RolesAllowed.class);
        if (rolesAllowed != null) {
            performAuthorization(rolesAllowed.value(), requestContext);
            return;
        }

        // @PermitAll on the class
        if (resourceInfo.getResourceClass().isAnnotationPresent(PermitAll.class)) {
            return;
        }

        // Authentication is required for non-annotated methods
        if (isNotAuthenticated(requestContext)) {
            throw new AccessDeniedException("Accessing user is not authenticated");
        }

    }

    /**
     * Perform authorization based on roles.
     *
     * @param rolesAllowed   {@link String}
     * @param requestContext {@link ContainerRequestContext}
     */
    private void performAuthorization(String[] rolesAllowed, ContainerRequestContext requestContext) {

        if (isNotAuthenticated(requestContext)) {
            throw new AccessDeniedException("Accessing user is not authenticated");
        }

        final SecurityContext securityContext = requestContext.getSecurityContext();
        for (final String role : rolesAllowed) {
            if (securityContext.isUserInRole(role)) {
                return;
            }
        }

        throw new AccessDeniedException("Access denied");
    }

    /**
     * Check if the user is authenticated.
     *
     * @param requestContext {@link ContainerRequestContext}
     * @return boolean
     */
    private boolean isNotAuthenticated(final ContainerRequestContext requestContext) {
        return requestContext.getSecurityContext().getUserPrincipal() == null;
    }

}