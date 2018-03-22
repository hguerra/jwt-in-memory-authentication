package br.com.carneiro.jwt.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Security Config
 */
@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * Protect against Cross-Site Request Forgery (CSRF) attack.
     *
     * Reference:
     * http://www.baeldung.com/spring-security-csrf
     * http://blog.caelum.com.br/protegendo-sua-aplicacao-web-contra-cross-site-request-forgerycsrf/
     *
     * @param http HttpSecurity
     * @throws Exception when failed
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/home").permitAll()
                .antMatchers(HttpMethod.POST, "/login").permitAll()
                .anyRequest().authenticated()
            .and()

            // filter login request
            .addFilterBefore(
                new JWTLoginFilter("/login",
                    authenticationManager()),
                UsernamePasswordAuthenticationFilter.class)

            // filter other request with JWT in Header
            .addFilterBefore(
                new JWTAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class);
    }

    /**
     * Authenticate the user using a database.
     *
     * @param auth AuthenticationManagerBuilder
     * @throws Exception when failed
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // initial test using a default account
        BCryptPasswordEncoder encoder = passwordEncoder();

        auth
            .inMemoryAuthentication()
            .passwordEncoder(encoder)
            .withUser("admin")
            .password(encoder.encode("password"))
            .roles("ADMIN");
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
