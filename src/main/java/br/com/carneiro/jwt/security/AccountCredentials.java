package br.com.carneiro.jwt.security;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AccountCredentials {

    private String username;

    private String password;
}
