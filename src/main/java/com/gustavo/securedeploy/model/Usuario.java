package com.gustavo.securedeploy.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Data;

@Data
@Entity
@Table(name = "usuarios")
public class Usuario {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    // Papel do usuário no sistema (Ex: ROLE_USER, ROLE_ADMIN)
    @Column(nullable = false)
    private String role;

    /* ==============================================================
     * CAMPOS DE TELEMETRIA PARA O ZERO TRUST (HEURÍSTICAS)
     * ============================================================== */
    
    @Column(name = "ultimo_ip_conhecido")
    private String ultimoIpConhecido;

    @Column(name = "ultimo_login")
    private LocalDateTime ultimoLogin;

    @Column(name = "tentativas_falhas")
    private int tentativasFalhas;

    @Column(name = "conta_bloqueada")
    private boolean contaBloqueada;
}