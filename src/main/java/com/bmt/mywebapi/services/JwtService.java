package com.bmt.mywebapi.services;

import com.bmt.mywebapi.models.AppUser;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class JwtService {

    @Value("${security.jwt.secret-key}")
    private String secretKey;

    @Value("${security.jwt.expiration-time-ms}")
    private long expirationTimeMs;

    @Value("${security.jwt.issuer}")
    private String issuer;

    // method to generate JWT
    public String createJwtToken(AppUser user) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        var key = Keys.hmacShaKeyFor(keyBytes);

        return Jwts
                .builder()
                .subject(user.getEmail())
                .issuedAt(new Date(System.currentTimeMillis()))
                .issuer(issuer)
                .expiration(new Date(System.currentTimeMillis() + expirationTimeMs))
                .signWith(key)
                .compact();
    }

    // this method allows us to verify the token
    public Claims getTokenClaims(String token) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        var key = Keys.hmacShaKeyFor(keyBytes);

        try {
            var claims = Jwts
                    .parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            Date expDate = claims.getExpiration();
            Date currentDate = new Date();
            if (currentDate.before(expDate)) {
                return claims;
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }

        // if the token is not valid, it will return null.
        return null;
    }

}
