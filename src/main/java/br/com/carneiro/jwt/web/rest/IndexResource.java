package br.com.carneiro.jwt.web.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IndexResource {

    @GetMapping("/home")
    public String index() {
        return "Hello";
    }

}
