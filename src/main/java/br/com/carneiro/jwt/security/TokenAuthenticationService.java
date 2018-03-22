package br.com.carneiro.jwt.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.val;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.Date;

/**
 *  This class is responsible to generate a validate JWT tokens.
 *
 *  In this example we use a token based on: username, expiration time and secret.
 */
public class TokenAuthenticationService {

    static final long EXPIRATION_TIME = 860_000_000; // 10 days
    static final String SECRET = "MySecret";
    static final String TOKEN_PREFIX = "Bearer";
    static final String HEADER_STRING = "Authorization";

    /**
     * JWT doc:
     *
     * HMACSHA256(
     *  base64UrlEncode(header) + "." +
     *  base64UrlEncode(payload),
     *  secret)
     *
     * Reference:
     * https://jwt.io/introduction/
     * @param response HttpServletResponse
     * @param username String
     */
    static void addAuthentication(HttpServletResponse response, String username) {
        val jwt = Jwts.builder()
            .setSubject(username) // [Registered claims] sub
            .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME)) // [Registered claims] exp
            .signWith(SignatureAlgorithm.HS512, SECRET) // Signature
            .compact(); // Putting all together

        // Authorization: Bearer <token>
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + " " + jwt);
    }

    static Authentication getAuthentication(HttpServletRequest request) {
        val token = request.getHeader(HEADER_STRING);

        if (token != null) {
            // parse the token
            val user = Jwts.parser()
                .setSigningKey(SECRET)
                .parseClaimsJws(token.replace(TOKEN_PREFIX, ""))
                .getBody()
                .getSubject();

            if (user != null) {
                // username, credentials and roles
                return new UsernamePasswordAuthenticationToken(user, null, Collections.emptyList());
            }
        }

        return null;
    }
}
