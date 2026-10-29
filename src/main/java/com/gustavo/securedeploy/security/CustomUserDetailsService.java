package com.gustavo.securedeploy.security;

import java.util.List;

import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.gustavo.securedeploy.model.Usuario;
import com.gustavo.securedeploy.repository.UsuarioRepository;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;

    public CustomUserDetailsService(UsuarioRepository usuarioRepository) {
        this.usuarioRepository = usuarioRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("Utilizador nao encontrado no sistema: " + username));

        // ZERO TRUST: Se a conta foi bloqueada por tentativas excessivas, rejeita o acesso aqui!
        if (usuario.isContaBloqueada()) {
            throw new LockedException("Acesso negado: Esta conta esta temporariamente bloqueada por motivos de seguranca.");
        }

        String role = usuario.getRole();
        if (role == null || role.trim().isEmpty()) {
            role = "ROLE_USER";
        } else {
            role = role.trim();
            if (!role.startsWith("ROLE_")) {
                role = "ROLE_" + role;
            }
        }

        List<SimpleGrantedAuthority> authorities = List.of(new SimpleGrantedAuthority(role));

        return new User(
                usuario.getUsername(),
                usuario.getPassword(),
                authorities
        );
    }
}
