package com.gustavo.securedeploy.controller;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import org.mockito.Mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gustavo.securedeploy.dto.LoginRequest;
import com.gustavo.securedeploy.dto.RegistroRequest;
import com.gustavo.securedeploy.model.Usuario;
import com.gustavo.securedeploy.repository.UsuarioRepository;
import com.gustavo.securedeploy.security.JwtUtil;

@ExtendWith(MockitoExtension.class)
class AuthControllerTest {

    private MockMvc mockMvc;

    @Mock
    private UsuarioRepository usuarioRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private AuthenticationManager authenticationManager;

    @Mock
    private JwtUtil jwtUtil;

    @Mock
    private UserDetailsService userDetailsService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        AuthController authController = new AuthController(
                usuarioRepository,
                passwordEncoder,
                authenticationManager,
                jwtUtil,
                userDetailsService
        );
        this.mockMvc = MockMvcBuilders.standaloneSetup(authController).build();
    }

    @Test
    @DisplayName("POST /api/auth/registo - Deve registrar novo usuario com sucesso como ROLE_USER")
    void deveRegistrarUsuarioComSucesso() throws Exception {
        RegistroRequest request = new RegistroRequest("novousuario", "senhaSegura123");

        when(usuarioRepository.findByUsername("novousuario")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("senhaSegura123")).thenReturn("hashSeguroBCrypt");

        mockMvc.perform(post("/api/auth/registo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.mensagem").value("Sucesso: Utilizador registado com seguranca!"));

        ArgumentCaptor<Usuario> usuarioCaptor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(usuarioCaptor.capture());
        assertEquals("ROLE_USER", usuarioCaptor.getValue().getRole());
    }

    @Test
    @DisplayName("POST /api/auth/registo - Tentativa de autoatribuicao de ROLE_ADMIN deve ser ignorada e gravada como ROLE_USER")
    void deveIgnorarTentativaDeAutoatribuicaoRoleAdmin() throws Exception {
        String payloadComRoleAdmin = "{\"username\":\"atacanteAdmin\",\"password\":\"senhaForte123\",\"role\":\"ROLE_ADMIN\"}";

        when(usuarioRepository.findByUsername("atacanteAdmin")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("senhaForte123")).thenReturn("hashSeguroBCrypt");

        mockMvc.perform(post("/api/auth/registo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payloadComRoleAdmin))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.mensagem").value("Sucesso: Utilizador registado com seguranca!"));

        ArgumentCaptor<Usuario> usuarioCaptor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(usuarioCaptor.capture());
        assertEquals("ROLE_USER", usuarioCaptor.getValue().getRole());
    }

    @Test
    @DisplayName("POST /api/auth/registo - Tentativa de envio de role=ADMIN deve ser ignorada e gravada como ROLE_USER")
    void deveIgnorarTentativaDeAutoatribuicaoAdminSemPrefixo() throws Exception {
        String payloadComAdmin = "{\"username\":\"atacanteAdmin2\",\"password\":\"senhaForte123\",\"role\":\"ADMIN\"}";

        when(usuarioRepository.findByUsername("atacanteAdmin2")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("senhaForte123")).thenReturn("hashSeguroBCrypt");

        mockMvc.perform(post("/api/auth/registo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(payloadComAdmin))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.mensagem").value("Sucesso: Utilizador registado com seguranca!"));

        ArgumentCaptor<Usuario> usuarioCaptor = ArgumentCaptor.forClass(Usuario.class);
        verify(usuarioRepository).save(usuarioCaptor.capture());
        assertEquals("ROLE_USER", usuarioCaptor.getValue().getRole());
    }

    @Test
    @DisplayName("POST /api/auth/registo - Deve retornar 400 quando username ja estiver em uso")
    void deveRetornar400QuandoUsernameJaExistir() throws Exception {
        RegistroRequest request = new RegistroRequest("usuarioExistente", "senhaSegura123");

        when(usuarioRepository.findByUsername("usuarioExistente")).thenReturn(Optional.of(new Usuario()));

        mockMvc.perform(post("/api/auth/registo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.erro").value("Erro: Este nome de utilizador ja esta em uso!"));

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    @DisplayName("POST /api/auth/registo - Deve retornar 400 na validacao de campo de username vazio")
    void deveRetornar400QuandoUsernameEmBranco() throws Exception {
        RegistroRequest request = new RegistroRequest("", "senhaValida123");

        mockMvc.perform(post("/api/auth/registo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.erro").exists());

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    @DisplayName("POST /api/auth/registo - Deve retornar 400 quando senha for menor que 6 caracteres")
    void deveRetornar400QuandoSenhaMuitoCurta() throws Exception {
        RegistroRequest request = new RegistroRequest("usuarioOk", "123");

        mockMvc.perform(post("/api/auth/registo")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.erro").exists());

        verify(usuarioRepository, never()).save(any(Usuario.class));
    }

    @Test
    @DisplayName("POST /api/auth/login - Deve autenticar com sucesso e retornar token JWT 200")
    void deveEfetuarLoginComSucesso() throws Exception {
        LoginRequest request = new LoginRequest("usuarioValido", "senhaCorreta");
        UserDetails userDetails = new User("usuarioValido", "hash", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        when(userDetailsService.loadUserByUsername("usuarioValido")).thenReturn(userDetails);
        when(jwtUtil.generateToken(userDetails)).thenReturn("jwt.token.mockado.2026");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.mensagem").value("Login efetuado com sucesso!"))
                .andExpect(jsonPath("$.token").value("jwt.token.mockado.2026"));

        verify(authenticationManager).authenticate(any(UsernamePasswordAuthenticationToken.class));
    }

    @Test
    @DisplayName("POST /api/auth/login - Deve retornar 400 na validacao de credenciais vazias")
    void deveRetornar400QuandoLoginSemSenha() throws Exception {
        LoginRequest request = new LoginRequest("usuario", "");

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.erro").exists());

        verify(authenticationManager, never()).authenticate(any());
    }

    @Test
    @DisplayName("POST /api/auth/login - Deve retornar 401 quando autenticacao falhar")
    void deveRetornar401QuandoCredenciaisInvalidas() throws Exception {
        LoginRequest request = new LoginRequest("usuarioInvalido", "senhaErrada");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenThrow(new BadCredentialsException("Credenciais invalidas"));

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.erro").value("Credenciais invalidas ou conta bloqueada!"));
    }
}
