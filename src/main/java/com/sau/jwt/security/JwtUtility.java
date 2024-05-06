package com.sau.jwt.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.hibernate.annotations.Comment;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtility {
    private static final long EXPIRATION_TIME = 86400000;
    private static final String SECRET_KEY = "$2a$12$e6Y5onc6D6n6UIGPWC9BJ.JJdxlFfhGBjzOxuqLBhGWIBWEyGdGvW";

    public static String createToken(Authentication authentication){ // Map<String, Object> claims,
        String username = authentication.getName();
        String roles = authentication.getAuthorities().toString();
        return Jwts.builder()
                .claims()
                .add("roles", roles)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .and()
                .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()), SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateJwtToken(String token, String username){
        final String usernameFromToken = getUsernameFromToken(token);
        return (username.equals(usernameFromToken) && !isTokenExpired(token));
    }

    public String getUsernameFromToken(String token){
        return getClaimFromToken(token, Claims::getSubject);
    }

    private boolean isTokenExpired(String token){
        final Date expiration = getExpirationDateFromToken(token);
        return expiration.before(new Date());
    }

    public Date getExpirationDateFromToken(String token){
        return getClaimFromToken(token, Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver){
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    public Claims getAllClaimsFromToken(String token){
        JwtParserBuilder parserBuilder = Jwts.parser(); //parserBuilder();
        parserBuilder.setSigningKey(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()));
        return parserBuilder.build().parseClaimsJws(token).getBody();
    }
}
