package com.gustavo.securedeploy.security;

import java.time.LocalDateTime;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import com.gustavo.securedeploy.model.Usuario;
import com.gustavo.securedeploy.repository.UsuarioRepository;

import jakarta.servlet.http.HttpServletRequest;

@Service
public class LoginAttemptService {

    private static final Logger logger = LoggerFactory.getLogger(LoginAttemptService.class);
    private static final int MAX_TENTATIVAS = 3;

    private final UsuarioRepository usuarioRepository;
    private final HttpServletRequest request;

    public LoginAttemptService(UsuarioRepository usuarioRepository, HttpServletRequest request) {
        this.usuarioRepository = usuarioRepository;
        this.request = request;
    }

    @EventListener
    public void loginFalhou(AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        String username = principal instanceof String ? (String) principal : principal.toString();
        
        Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);

        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            
            if (!usuario.isContaBloqueada()) {
                usuario.setTentativasFalhas(usuario.getTentativasFalhas() + 1);
                
                if (usuario.getTentativasFalhas() >= MAX_TENTATIVAS) {
                    usuario.setContaBloqueada(true);
                    logger.warn("Alerta de seguranca: Conta bloqueada por excesso de tentativas falhas: {}", username);
                }
                
                usuarioRepository.save(usuario);
            }
        }
    }

    @EventListener
    public void loginTeveSucesso(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        String username;
        if (principal instanceof User springUser) {
            username = springUser.getUsername();
        } else {
            username = principal.toString();
        }
        
        Optional<Usuario> usuarioOpt = usuarioRepository.findByUsername(username);

        if (usuarioOpt.isPresent()) {
            Usuario usuario = usuarioOpt.get();
            
            usuario.setTentativasFalhas(0);
            usuario.setContaBloqueada(false);
            usuario.setUltimoLogin(LocalDateTime.now());
            
            if (request != null) {
                String ipClient = request.getRemoteAddr();
                usuario.setUltimoIpConhecido(ipClient);
            }
            
            usuarioRepository.save(usuario);
        }
    }
}
