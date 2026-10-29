package com.gustavo.securedeploy.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.gustavo.securedeploy.model.Usuario;

@Repository
public interface UsuarioRepository extends JpaRepository<Usuario, Long> {
    
    // O Spring Data faz a mágica de criar a consulta SQL sozinho apenas pelo nome do método!
    Optional<Usuario> findByUsername(String username);
}