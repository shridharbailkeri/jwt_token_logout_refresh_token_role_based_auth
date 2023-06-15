package com.alibou.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service // to transform it to managed bean 
public class JwtService {

    //https://allkeysgenerator.com/Random/Security-Encryption-key-Generator.aspx
    @Value("${application.security.jwt.secret-key}")
    private String secretKey;

    @Value("${application.security.jwt.expiration}")
    private long jwtExpiration;

    @Value("${application.security.jwt.refresh-token.expiration}")
    private long refreshExpiration;

    // step 4
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject); // getSubject should be mail or user name of my user
    }
    // step 3
    // method to extract single claim that we pass
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims); // now extracted all claims now extracting any single claim from token will be easy
    }
    // step 6
    // generate token without extra claims
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }
    // step 5
    // token is a string
    // for us user name is email for spring we communicate email as username
    public String generateToken(Map<String, Objects> extraClaims,
                                UserDetails userDetails) {
        return buildToken(extraClaims, userDetails, jwtExpiration);
    }

    public String generateRefreshToken(
                                UserDetails userDetails) {
        return buildToken(new HashMap<>(), userDetails, refreshExpiration);
    }

    private String buildToken(Map<String, Objects> extraClaims,
                              UserDetails userDetails,
                              long expiration) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expiration))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact(); // compact generates and returns the token
    }
    // step 7
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
        // userDetails.getUsername() extracts the user from database and gets username
        // extractUsername(token) gets user name from token which inturn is got from http request
    }

    private boolean isTokenExpired(String token) {
        // to make sure it is before todays date before(new Date());
        // If the expiration date is before the current date and time, the method returns true,
        // indicating that the token has expired.
        //Otherwise, if the expiration date is on or after the current date and time,
        // the method returns false, indicating that the token is still valid
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    // step 1
    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody(); // here we get all claims that are in the passed token
    }

    // step 2
    private Key getSignInKey() {
        byte[] keyBites = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBites);
    }
}
