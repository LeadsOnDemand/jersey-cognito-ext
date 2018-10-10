package com.leadsondemand.jersey.security.cognito;

import com.anigenero.junit.mockito.MockitoExtension;
import com.leadsondemand.jersey.security.cognito.service.AuthenticationTokenService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;

import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.SecurityContext;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthenticationFilterTest {

    @Mock
    private AuthenticationTokenService mockAuthenticationTokenService;

    private AuthenticationFilter authenticationFilter;

    @BeforeEach
    void setup() {
        this.authenticationFilter = new AuthenticationFilter(mockAuthenticationTokenService);
    }

    @Test
    void testDefaultConstructor() {
        new AuthenticationFilter();
    }

    @Test
    void testValidFilter() {

        final ContainerRequestContext mockContainerRequest = mock(ContainerRequestContext.class);
        final SecurityContext mockSecurityContext = mock(SecurityContext.class);

        final Set<String> roles = new HashSet<>(Arrays.asList("update", "delete"));

        final AuthorizationContext authorizationContext = new AuthorizationContext("foobar", roles);

        ArgumentCaptor<TokenBasedSecurityContext> tokenCaptor = ArgumentCaptor.forClass(TokenBasedSecurityContext.class);

        when(mockContainerRequest.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer 1234567890");

        when(mockAuthenticationTokenService.parseToken(any())).thenReturn(authorizationContext);

        when(mockContainerRequest.getSecurityContext()).thenReturn(mockSecurityContext);
        when(mockSecurityContext.isSecure()).thenReturn(true);

        doNothing().when(mockContainerRequest).setSecurityContext(tokenCaptor.capture());

        this.authenticationFilter.filter(mockContainerRequest);

        verify(mockContainerRequest).getHeaderString(HttpHeaders.AUTHORIZATION);

        verify(mockAuthenticationTokenService).parseToken(any());

        verify(mockContainerRequest).getSecurityContext();
        verify(mockSecurityContext).isSecure();

        final TokenBasedSecurityContext context = tokenCaptor.getValue();

        assertThat(context).isNotNull();
        assertThat(context.getAuthenticationScheme()).isEqualTo("Bearer");
        assertThat(context.getAuthorizationContext()).isEqualTo(authorizationContext);
        assertThat(context.getUserPrincipal()).isInstanceOf(AuthenticatedUserDetails.class);
        assertThat(context.getUserPrincipal().getName()).isNull();
        assertThat(((AuthenticatedUserDetails) context.getUserPrincipal()).getRoles()).isEqualTo(roles);

    }

    @Test
    void testInvalidFilter() {

        final ContainerRequestContext mockContainerRequest = mock(ContainerRequestContext.class);
        final SecurityContext mockSecurityContext = mock(SecurityContext.class);

        ArgumentCaptor<TokenBasedSecurityContext> tokenCaptor = ArgumentCaptor.forClass(TokenBasedSecurityContext.class);

        when(mockContainerRequest.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn("invalid");
        doNothing().when(mockContainerRequest).setSecurityContext(tokenCaptor.capture());

        when(mockContainerRequest.getSecurityContext()).thenReturn(mockSecurityContext);
        when(mockSecurityContext.isSecure()).thenReturn(true);

        this.authenticationFilter.filter(mockContainerRequest);

        verify(mockContainerRequest).getHeaderString(HttpHeaders.AUTHORIZATION);
        verify(mockContainerRequest).getSecurityContext();
        verify(mockSecurityContext).isSecure();

        final TokenBasedSecurityContext context = tokenCaptor.getValue();

        assertThat(context).isNotNull();
        assertThat(context.getAuthenticationScheme()).isEqualTo("Bearer");
        assertThat(context.getAuthorizationContext()).isNull();
        assertThat(context.getUserPrincipal()).isNull();

    }

    @Test
    void testInvalidFilterWithNullHeader() {

        final ContainerRequestContext mockContainerRequest = mock(ContainerRequestContext.class);
        final SecurityContext mockSecurityContext = mock(SecurityContext.class);

        ArgumentCaptor<TokenBasedSecurityContext> tokenCaptor = ArgumentCaptor.forClass(TokenBasedSecurityContext.class);

        when(mockContainerRequest.getHeaderString(HttpHeaders.AUTHORIZATION)).thenReturn(null);
        doNothing().when(mockContainerRequest).setSecurityContext(tokenCaptor.capture());

        when(mockContainerRequest.getSecurityContext()).thenReturn(mockSecurityContext);
        when(mockSecurityContext.isSecure()).thenReturn(true);

        this.authenticationFilter.filter(mockContainerRequest);

        verify(mockContainerRequest).getHeaderString(HttpHeaders.AUTHORIZATION);
        verify(mockContainerRequest).getSecurityContext();
        verify(mockSecurityContext).isSecure();

        final TokenBasedSecurityContext context = tokenCaptor.getValue();

        assertThat(context).isNotNull();
        assertThat(context.getAuthenticationScheme()).isEqualTo("Bearer");
        assertThat(context.getAuthorizationContext()).isNull();
        assertThat(context.getUserPrincipal()).isNull();

    }

}