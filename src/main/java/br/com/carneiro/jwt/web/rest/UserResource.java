package br.com.carneiro.jwt.web.rest;

import br.com.carneiro.jwt.domain.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
public class UserResource {

    @GetMapping("/users")
    public List<User> getUsers() {
        return Arrays.asList(new User("Heitor", "Brazil"), new User("Fabiana", "Brazil"));
    }

}
