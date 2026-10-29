package com.gustavo.securedeploy.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "O nome de utilizador e obrigatorio")
    private String username;

    @NotBlank(message = "A palavra-passe e obrigatoria")
    private String password;
}

