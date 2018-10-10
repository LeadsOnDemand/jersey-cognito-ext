package com.leadsondemand.jersey.security.cognito;

import com.anigenero.junit.mockito.MockitoExtension;
import com.leadsondemand.jersey.security.cognito.exception.AccessDeniedException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.stubbing.Answer;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ResourceInfo;
import javax.ws.rs.core.SecurityContext;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthorizationFilterTest {

    @Mock
    private ContainerRequestContext mockContainerRequestContext;
    @Mock
    private ResourceInfo mockResourceInfo;

    private AuthorizationFilter authorizationFilter;

    @BeforeEach
    void setup() {

        this.mockContainerRequestContext = mock(ContainerRequestContext.class);
        this.mockResourceInfo = mock(ResourceInfo.class);
        this.authorizationFilter = new AuthorizationFilter(mockResourceInfo);

    }

    @Test
    void testNoArgConstructor() {
        new AuthorizationFilter();
    }

    @Test
    void testDenyAll() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("denyAll");

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();

    }

    @Test
    void testAllowedRolesWithNoPrincipal() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("rolesAllowed");

        final SecurityContext securityContext = new TokenBasedSecurityContext(null, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext).getSecurityContext();

    }

    @Test
    void testAllowedRolesWithPrincipalAndImproperRole() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("rolesAllowed");

        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(new HashSet<>(Collections.singletonList("loser")), "joe.dirt");

        final SecurityContext securityContext = new TokenBasedSecurityContext(userDetails, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext, atMost(2)).getSecurityContext();

    }

    @Test
    void testAllowedRolesWithPrincipalAndProperRole() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("rolesAllowed");

        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(new HashSet<>(Collections.singletonList("admin")), "joe.dirt");

        final SecurityContext securityContext = new TokenBasedSecurityContext(userDetails, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        this.authorizationFilter.filter(this.mockContainerRequestContext);

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext, atMost(2)).getSecurityContext();

    }

    @Test
    void testPermitAllMethodWithAuthentication() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("permitAll");

        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(new HashSet<>(Collections.singletonList("manager")), "joe.dirt");

        final SecurityContext securityContext = new TokenBasedSecurityContext(userDetails, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        this.authorizationFilter.filter(this.mockContainerRequestContext);

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext, atMost(2)).getSecurityContext();

    }

    @Test
    void testPermitAllMethodWithAnonymous() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("permitAll");
        final SecurityContext securityContext = new TokenBasedSecurityContext(null, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        this.authorizationFilter.filter(this.mockContainerRequestContext);

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext, atMost(2)).getSecurityContext();

    }

    @Test
    void testPermitAllMethodWithNoAnnotationAndAuthenticated() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("noAnnotation");
        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(new HashSet<>(Collections.singletonList("manager")), "joe.dirt");
        final SecurityContext securityContext = new TokenBasedSecurityContext(userDetails, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockResourceInfo.getResourceClass()).thenAnswer((Answer<Object>) invocation -> TestService.class);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        this.authorizationFilter.filter(this.mockContainerRequestContext);

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockResourceInfo).getResourceClass();
        verify(this.mockContainerRequestContext).getSecurityContext();

    }

    @Test
    void testPermitAllMethodWithNoAnnotationAndAnonymous() throws Exception {

        final Method method = TestService.class.getDeclaredMethod("noAnnotation");
        final SecurityContext securityContext = new TokenBasedSecurityContext(null, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockResourceInfo.getResourceClass()).thenAnswer((Answer<Object>) invocation -> TestService.class);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockResourceInfo).getResourceClass();
        verify(this.mockContainerRequestContext).getSecurityContext();

    }

    @Test
    void testDenyAllOnPermitAllService() throws Exception {

        final Method method = PermitAllService.class.getDeclaredMethod("denyAll");

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();

    }

    @Test
    void testAllowedRolesWithNoPrincipalOnPermitAllService() throws Exception {

        final Method method = PermitAllService.class.getDeclaredMethod("rolesAllowed");

        final SecurityContext securityContext = new TokenBasedSecurityContext(null, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext).getSecurityContext();

    }

    @Test
    void testAllowedRolesWithPrincipalAndImproperRoleOnPermitAllService() throws Exception {

        final Method method = PermitAllService.class.getDeclaredMethod("rolesAllowed");

        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(new HashSet<>(Collections.singletonList("loser")), "joe.dirt");

        final SecurityContext securityContext = new TokenBasedSecurityContext(userDetails, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        assertThrows(AccessDeniedException.class, () -> this.authorizationFilter.filter(this.mockContainerRequestContext));

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext, atMost(2)).getSecurityContext();

    }

    @Test
    void testAllowedRolesWithPrincipalAndProperRoleOnPermitAllService() throws Exception {

        final Method method = PermitAllService.class.getDeclaredMethod("rolesAllowed");

        final AuthenticatedUserDetails userDetails = new AuthenticatedUserDetails(new HashSet<>(Collections.singletonList("admin")), "joe.dirt");

        final SecurityContext securityContext = new TokenBasedSecurityContext(userDetails, null, true);

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockContainerRequestContext.getSecurityContext()).thenReturn(securityContext);

        this.authorizationFilter.filter(this.mockContainerRequestContext);

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockContainerRequestContext, atMost(2)).getSecurityContext();

    }

    @Test
    void testNoAnnotationMethodOnPermitAllService() throws Exception {

        final Method method = PermitAllService.class.getDeclaredMethod("noAnnotation");

        when(this.mockResourceInfo.getResourceMethod()).thenReturn(method);
        when(this.mockResourceInfo.getResourceClass()).thenAnswer((Answer<Object>) invocation -> PermitAllService.class);

        this.authorizationFilter.filter(this.mockContainerRequestContext);

        verify(this.mockResourceInfo).getResourceMethod();
        verify(this.mockResourceInfo).getResourceClass();

    }

    @SuppressWarnings({"WeakerAccess", "EmptyMethod"})
    public static class TestService {

        @DenyAll
        void denyAll() {
        }

        @RolesAllowed({"admin"})
        void rolesAllowed() {

        }

        @PermitAll
        void permitAll() {

        }

        void noAnnotation() {

        }

    }

    @SuppressWarnings({"WeakerAccess", "EmptyMethod"})
    @PermitAll
    public static class PermitAllService {

        @DenyAll
        void denyAll() {
        }

        @RolesAllowed({"admin"})
        void rolesAllowed() {

        }

        void noAnnotation() {

        }

    }

}