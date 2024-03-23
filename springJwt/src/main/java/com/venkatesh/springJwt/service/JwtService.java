package com.venkatesh.springJwt.service;

import com.venkatesh.springJwt.model.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.function.Function;
@Service
public class JwtService {
    private final String SECRET_KEY="5e49c82aca5bdc97d7c166b1cd62d94d8cf4fc0555611c20390e146191c454c5";

    public String extractUsername(String token){
        return extractClaim(token,Claims::getSubject);
    }
    public boolean isValid(String token, UserDetails userDetails){
        String username=extractUsername(token);
        return (username.equals(userDetails.getUsername())&&!isTokenExpired(token)  );
    }
    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());

    }
    private Date extractExpiration(String token){
        return extractClaim(token,Claims::getExpiration);
    }
    public <T> T extractClaim(String token, Function<Claims,T> resolver){
        Claims claims=extractAllClaims(token);
        return resolver.apply(claims);
    }

    private Claims extractAllClaims(String token){
        return Jwts
                .parser()
                .verifyWith(getSignKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String generateToken(User user){
        String token = Jwts
                .builder()
                .subject(user.getUsername())
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis()+24*60*60*1000))
                .signWith(getSignKey())
                .compact();
        return token;
    }
    private SecretKey getSignKey(){
        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
