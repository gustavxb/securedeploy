package com.gustavo.securedeploy.security;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;

class JwtUtilTest {

    private static final String CHAVE_VALIDA = "chave_secreta_jwt_de_alta_complexidade_para_testes_secbot_2026!";
    private static final long EXPIRACAO_PADRAO = 3600000L; // 1 hora

    @Test
    @DisplayName("Deve lancar IllegalStateException quando a chave JWT for nula ou em branco")
    void deveLancarExcecaoQuandoChaveSecretaForAusenteOuNula() {
        IllegalStateException ex1 = assertThrows(IllegalStateException.class, () -> new JwtUtil(null, EXPIRACAO_PADRAO));
        assertTrue(ex1.getMessage().contains("ausente"));

        IllegalStateException ex2 = assertThrows(IllegalStateException.class, () -> new JwtUtil("   ", EXPIRACAO_PADRAO));
        assertTrue(ex2.getMessage().contains("ausente"));
    }

    @Test
    @DisplayName("Deve lancar IllegalStateException quando a chave JWT possuir menos de 32 caracteres (256 bits)")
    void deveLancarExcecaoQuandoChaveSecretaForCurta() {
        String chaveCurta = "chave_menor_que_32_bytes"; // 24 chars
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> new JwtUtil(chaveCurta, EXPIRACAO_PADRAO));
        assertTrue(ex.getMessage().contains("no minimo 256 bits"));
    }

    @Test
    @DisplayName("Deve lancar IllegalStateException quando a expiracao JWT for zero ou negativa")
    void deveLancarExcecaoQuandoExpiracaoForZeroOuNegativa() {
        IllegalStateException exZero = assertThrows(IllegalStateException.class, () -> new JwtUtil(CHAVE_VALIDA, 0));
        assertTrue(exZero.getMessage().contains("estritamente positivo"));

        IllegalStateException exNeg = assertThrows(IllegalStateException.class, () -> new JwtUtil(CHAVE_VALIDA, -5000));
        assertTrue(exNeg.getMessage().contains("estritamente positivo"));
    }

    @Test
    @DisplayName("Deve gerar e validar token JWT com sucesso quando chave valida for fornecida")
    void deveGerarEValidarTokenComSucesso() {
        JwtUtil jwtUtil = new JwtUtil(CHAVE_VALIDA, EXPIRACAO_PADRAO);
        UserDetails userDetails = new User(
                "analista_seguranca",
                "senha123",
                List.of(new SimpleGrantedAuthority("ROLE_USER"))
        );

        String token = jwtUtil.generateToken(userDetails);

        assertNotNull(token);
        assertFalse(token.isBlank());
        assertEquals("analista_seguranca", jwtUtil.extractUsername(token));
        assertTrue(jwtUtil.validateToken(token, userDetails));
        assertNotNull(jwtUtil.extractExpiration(token));
        assertFalse(jwtUtil.isTokenExpired(token));
    }

    @Test
    @DisplayName("Deve rejeitar token quando validado com usuario divergente")
    void deveRejeitarTokenComUsuarioDivergente() {
        JwtUtil jwtUtil = new JwtUtil(CHAVE_VALIDA, EXPIRACAO_PADRAO);
        UserDetails user1 = new User("usuario1", "hash", List.of());
        UserDetails user2 = new User("usuario2", "hash", List.of());

        String tokenUser1 = jwtUtil.generateToken(user1);

        assertFalse(jwtUtil.validateToken(tokenUser1, user2));
    }

    @Test
    @DisplayName("Deve rejeitar token expirado e retornar false no validateToken")
    void deveRejeitarTokenExpirado() throws InterruptedException {
        // Token com expiracao curtissima de 5ms
        JwtUtil jwtUtil = new JwtUtil(CHAVE_VALIDA, 5L);
        UserDetails user = new User("usuarioExpirado", "hash", List.of());

        String token = jwtUtil.generateToken(user);

        // Aguarda 20ms para garantir expiracao do token
        Thread.sleep(20);

        assertTrue(jwtUtil.isTokenExpired(token));
        assertFalse(jwtUtil.validateToken(token, user));
        assertThrows(ExpiredJwtException.class, () -> jwtUtil.extractUsername(token));
    }

    @Test
    @DisplayName("Deve rejeitar token malformado ou invalido com seguranca")
    void deveRejeitarTokenMalformado() {
        JwtUtil jwtUtil = new JwtUtil(CHAVE_VALIDA, EXPIRACAO_PADRAO);
        UserDetails user = new User("usuarioQualquer", "hash", List.of());

        assertFalse(jwtUtil.validateToken("token.malformado.invalido", user));
        assertFalse(jwtUtil.validateToken("", user));
        assertFalse(jwtUtil.validateToken(null, user));
        assertThrows(MalformedJwtException.class, () -> jwtUtil.extractUsername("token.invalido"));
    }

    @Test
    @DisplayName("Deve rejeitar token com assinatura adulterada por chave diferente")
    void deveRejeitarTokenComAssinaturaAdulterada() {
        String outraChave = "outra_chave_com_mais_de_32_caracteres_diferente!";
        JwtUtil jwtUtilEmissor = new JwtUtil(outraChave, EXPIRACAO_PADRAO);
        JwtUtil jwtUtilValidador = new JwtUtil(CHAVE_VALIDA, EXPIRACAO_PADRAO);

        UserDetails user = new User("usuarioAdulterado", "hash", List.of());
        String tokenComOutraChave = jwtUtilEmissor.generateToken(user);

        // O validador assinado com chave diferente deve rejeitar
        assertFalse(jwtUtilValidador.validateToken(tokenComOutraChave, user));
    }
}
