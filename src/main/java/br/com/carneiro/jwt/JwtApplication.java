package br.com.carneiro.jwt;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * This application is simple example of Spring Boot Security with JWT.
 *
 * References:
 * https://jwt.io/introduction/
 * http://andreybleme.com/2017-04-01/autenticacao-com-jwt-no-spring-boot/
 */
@SpringBootApplication
public class JwtApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }
}
