package com.gustavo.securedeploy.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class RegistroRequest {

    @NotBlank(message = "O nome de utilizador e obrigatorio")
    @Size(min = 3, max = 50, message = "O nome de utilizador deve ter entre 3 e 50 caracteres")
    private String username;

    @NotBlank(message = "A palavra-passe e obrigatoria")
    @Size(min = 6, max = 100, message = "A palavra-passe deve ter entre 6 e 100 caracteres")
    private String password;
}
