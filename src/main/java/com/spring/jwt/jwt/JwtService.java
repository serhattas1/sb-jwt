package com.spring.jwt.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Component
public class JwtService {

    public static final String SECRET_KEY = "ngo3lVRifi/xFmEp77z58iMw1Pj90ZWvYw9nYz/atns=";

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60))// 1 hour
                .signWith(SignatureAlgorithm.HS256, getSigningKey())
                .compact();
    }

    public Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public <T> T exportToken(String token, Function<Claims, T> claimsResolver) {
        Claims claims = Jwts.parser()
                .setSigningKey(getSigningKey())
                .parseClaimsJws(token)
                .getBody();

        return claimsResolver.apply(claims);
    }

    //Token içinden kullanıcı adını almak için
    public String getUserNameByToken(String token) {
        return exportToken(token, Claims::getSubject);
    }

    public boolean isTokenExpired(String token) {
        return exportToken(token, Claims::getExpiration).before(new Date());
    }
}

