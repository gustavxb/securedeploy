package com.gustavo.securedeploy.security;

import java.io.IOException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@ExtendWith(MockitoExtension.class)
class JwtRequestFilterTest {

    @Mock
    private CustomUserDetailsService userDetailsService;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    private JwtRequestFilter filter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        filter = new JwtRequestFilter(userDetailsService, jwtUtil);
    }

    @Test
    @DisplayName("Deve autenticar usuario no SecurityContext quando token Bearer valido for fornecido")
    void deveAutenticarQuandoBearerTokenValido() throws ServletException, IOException {
        String tokenValido = "token.jwt.valido";
        UserDetails userDetails = new User("usuarioTeste", "hash", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        when(request.getHeader("Authorization")).thenReturn("Bearer " + tokenValido);
        when(jwtUtil.extractUsername(tokenValido)).thenReturn("usuarioTeste");
        when(userDetailsService.loadUserByUsername("usuarioTeste")).thenReturn(userDetails);
        when(jwtUtil.validateToken(tokenValido, userDetails)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        assertNotNull(auth, "Authentication deve estar presente no contexto de seguranca");
        assertEquals("usuarioTeste", ((UserDetails) auth.getPrincipal()).getUsername());
        verify(filterChain).doFilter(request, response);
    }

    @Test
    @DisplayName("Nao deve autenticar quando header Authorization estiver ausente")
    void naoDeveAutenticarQuandoHeaderAusente() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn(null);

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verify(jwtUtil, never()).extractUsername(any());
    }

    @Test
    @DisplayName("Nao deve autenticar quando header Authorization nao iniciar com Bearer ")
    void naoDeveAutenticarQuandoHeaderNaoIniciaComBearer() throws ServletException, IOException {
        when(request.getHeader("Authorization")).thenReturn("Basic dXNlcjpwYXNz");

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verify(jwtUtil, never()).extractUsername(any());
    }

    @Test
    @DisplayName("Nao deve autenticar quando token Bearer for invalido ou expirado")
    void naoDeveAutenticarQuandoTokenInvalido() throws ServletException, IOException {
        String tokenInvalido = "token.invalido";

        when(request.getHeader("Authorization")).thenReturn("Bearer " + tokenInvalido);
        when(jwtUtil.extractUsername(tokenInvalido)).thenThrow(new RuntimeException("Token expirado"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(filterChain).doFilter(request, response);
        verify(userDetailsService, never()).loadUserByUsername(any());
    }

    @Test
    @DisplayName("Nao deve sobrescrever autenticacao se contexto ja estiver autenticado")
    void naoDeveSobrescreverAutenticacaoExistente() throws ServletException, IOException {
        Authentication authExistente = new UsernamePasswordAuthenticationToken("outroUsuario", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(authExistente);

        when(request.getHeader("Authorization")).thenReturn("Bearer token.qualquer");
        when(jwtUtil.extractUsername("token.qualquer")).thenReturn("novoUsuario");

        filter.doFilterInternal(request, response, filterChain);

        assertEquals("outroUsuario", SecurityContextHolder.getContext().getAuthentication().getPrincipal());
        verify(userDetailsService, never()).loadUserByUsername(any());
        verify(filterChain).doFilter(request, response);
    }
}

