package com.gustavo.securedeploy.security;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import static org.mockito.Mockito.when;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.gustavo.securedeploy.model.Usuario;
import com.gustavo.securedeploy.repository.UsuarioRepository;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UsuarioRepository usuarioRepository;

    private CustomUserDetailsService service;

    @BeforeEach
    void setUp() {
        service = new CustomUserDetailsService(usuarioRepository);
    }

    @Test
    @DisplayName("Deve carregar autoridades do usuario respeitando a role com prefixo ROLE_")
    void deveCarregarUsuarioComRoleFormatadaCorretamente() {
        Usuario usuario = new Usuario();
        usuario.setUsername("secuser");
        usuario.setPassword("hash123");
        usuario.setRole("ROLE_USER");
        usuario.setContaBloqueada(false);

        when(usuarioRepository.findByUsername("secuser")).thenReturn(Optional.of(usuario));

        UserDetails userDetails = service.loadUserByUsername("secuser");

        assertNotNull(userDetails);
        assertEquals("secuser", userDetails.getUsername());
        assertEquals(1, userDetails.getAuthorities().size());
        GrantedAuthority auth = userDetails.getAuthorities().iterator().next();
        assertEquals("ROLE_USER", auth.getAuthority());
    }

    @Test
    @DisplayName("Deve normalizar role adicionando prefixo ROLE_ quando nao existir")
    void deveNormalizarRoleSemPrefixoRole() {
        Usuario usuario = new Usuario();
        usuario.setUsername("adminuser");
        usuario.setPassword("hash123");
        usuario.setRole("ADMIN");
        usuario.setContaBloqueada(false);

        when(usuarioRepository.findByUsername("adminuser")).thenReturn(Optional.of(usuario));

        UserDetails userDetails = service.loadUserByUsername("adminuser");

        assertEquals(1, userDetails.getAuthorities().size());
        assertEquals("ROLE_ADMIN", userDetails.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    @DisplayName("Deve atribuir ROLE_USER padrao quando role for nula ou em branco")
    void deveAtribuirRolePadraoQuandoRoleForNulaOuEmBranco() {
        Usuario usuario = new Usuario();
        usuario.setUsername("defaultuser");
        usuario.setPassword("hash123");
        usuario.setRole("   ");
        usuario.setContaBloqueada(false);

        when(usuarioRepository.findByUsername("defaultuser")).thenReturn(Optional.of(usuario));

        UserDetails userDetails = service.loadUserByUsername("defaultuser");

        assertEquals("ROLE_USER", userDetails.getAuthorities().iterator().next().getAuthority());
    }

    @Test
    @DisplayName("Deve lancar LockedException quando a conta do usuario estiver bloqueada por seguranca")
    void deveLancarLockedExceptionQuandoContaBloqueada() {
        Usuario usuario = new Usuario();
        usuario.setUsername("bloqueado");
        usuario.setPassword("hash123");
        usuario.setContaBloqueada(true);

        when(usuarioRepository.findByUsername("bloqueado")).thenReturn(Optional.of(usuario));

        LockedException ex = assertThrows(LockedException.class, () -> service.loadUserByUsername("bloqueado"));
        assertTrue(ex.getMessage().contains("bloqueada"));
    }

    @Test
    @DisplayName("Deve lancar UsernameNotFoundException quando o usuario nao for encontrado no repositorio")
    void deveLancarUsernameNotFoundExceptionQuandoNaoEncontrado() {
        when(usuarioRepository.findByUsername("fantasma")).thenReturn(Optional.empty());

        assertThrows(UsernameNotFoundException.class, () -> service.loadUserByUsername("fantasma"));
    }
}

