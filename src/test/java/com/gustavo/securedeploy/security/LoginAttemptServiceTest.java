package com.gustavo.securedeploy.security;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.Mock;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

import com.gustavo.securedeploy.model.Usuario;
import com.gustavo.securedeploy.repository.UsuarioRepository;

import jakarta.servlet.http.HttpServletRequest;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private HttpServletRequest request;

    private LoginAttemptService service;

    @BeforeEach
    void setUp() {
        service = new LoginAttemptService(usuarioRepository, request);
    }

    @Test
    @DisplayName("Deve incrementar tentativas falhas na primeira e segunda falha sem bloquear a conta")
    void deveIncrementarTentativasFalhasSemBloquear() {
        Usuario usuario = new Usuario();
        usuario.setUsername("vitima");
        usuario.setTentativasFalhas(0);
        usuario.setContaBloqueada(false);

        when(usuarioRepository.findByUsername("vitima")).thenReturn(Optional.of(usuario));

        Authentication auth = new UsernamePasswordAuthenticationToken("vitima", "senhaErrada");
        AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
                auth, new BadCredentialsException("Senha incorreta"));

        // 1a tentativa falha
        service.loginFalhou(event);
        assertEquals(1, usuario.getTentativasFalhas());
        assertFalse(usuario.isContaBloqueada());
        verify(usuarioRepository).save(usuario);

        // 2a tentativa falha
        service.loginFalhou(event);
        assertEquals(2, usuario.getTentativasFalhas());
        assertFalse(usuario.isContaBloqueada());
    }

    @Test
    @DisplayName("Deve bloquear a conta ao atingir 3 tentativas falhas consecutivas (MAX_TENTATIVAS)")
    void deveBloquearContaAposTresTentativasFalhas() {
        Usuario usuario = new Usuario();
        usuario.setUsername("alvoBruteForce");
        usuario.setTentativasFalhas(2);
        usuario.setContaBloqueada(false);

        when(usuarioRepository.findByUsername("alvoBruteForce")).thenReturn(Optional.of(usuario));

        Authentication auth = new UsernamePasswordAuthenticationToken("alvoBruteForce", "senhaErrada");
        AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
                auth, new BadCredentialsException("Senha incorreta"));

        service.loginFalhou(event);

        assertEquals(3, usuario.getTentativasFalhas());
        assertTrue(usuario.isContaBloqueada(), "Conta deve ser bloqueada ao atingir o limite maximo de tentativas");
        verify(usuarioRepository).save(usuario);
    }

    @Test
    @DisplayName("Nao deve incrementar contador se a conta ja estiver bloqueada")
    void naoDeveIncrementarQuandoContaJaBloqueada() {
        Usuario usuario = new Usuario();
        usuario.setUsername("bloqueadoAnteriormente");
        usuario.setTentativasFalhas(3);
        usuario.setContaBloqueada(true);

        when(usuarioRepository.findByUsername("bloqueadoAnteriormente")).thenReturn(Optional.of(usuario));

        Authentication auth = new UsernamePasswordAuthenticationToken("bloqueadoAnteriormente", "senhaErrada");
        AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
                auth, new BadCredentialsException("Conta bloqueada"));

        service.loginFalhou(event);

        assertEquals(3, usuario.getTentativasFalhas());
        assertTrue(usuario.isContaBloqueada());
        verify(usuarioRepository, never()).save(usuario);
    }

    @Test
    @DisplayName("Deve resetar tentativas falhas, desbloquear e atualizar IP no login bem-sucedido")
    void deveResetarTentativasFalhasNoLoginComSucesso() {
        Usuario usuario = new Usuario();
        usuario.setUsername("usuarioRecuperado");
        usuario.setTentativasFalhas(2);
        usuario.setContaBloqueada(false);

        when(usuarioRepository.findByUsername("usuarioRecuperado")).thenReturn(Optional.of(usuario));
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");

        User springUser = new User("usuarioRecuperado", "hash", List.of());
        Authentication auth = mock(Authentication.class);
        when(auth.getPrincipal()).thenReturn(springUser);

        AuthenticationSuccessEvent event = new AuthenticationSuccessEvent(auth);

        service.loginTeveSucesso(event);

        assertEquals(0, usuario.getTentativasFalhas());
        assertFalse(usuario.isContaBloqueada());
        assertEquals("192.168.1.100", usuario.getUltimoIpConhecido());
        assertNotNull(usuario.getUltimoLogin());
        verify(usuarioRepository).save(usuario);
    }

    @Test
    @DisplayName("Nao deve falhar evento de login para usuario inexistente no sistema")
    void naoDeveFalharQuandoUsuarioInexistente() {
        when(usuarioRepository.findByUsername("inexistente")).thenReturn(Optional.empty());

        Authentication auth = new UsernamePasswordAuthenticationToken("inexistente", "senha");
        AuthenticationFailureBadCredentialsEvent event = new AuthenticationFailureBadCredentialsEvent(
                auth, new BadCredentialsException("Inexistente"));

        service.loginFalhou(event);

        verify(usuarioRepository, never()).save(any());
    }
}

