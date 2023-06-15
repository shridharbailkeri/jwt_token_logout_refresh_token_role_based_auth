package com.alibou.security.auth;

import com.alibou.security.UserRepository;
import com.alibou.security.config.JwtService;
import com.alibou.security.token.Token;
import com.alibou.security.token.TokenRepository;
import com.alibou.security.token.TokenType;
import com.alibou.security.user.Role;
import com.alibou.security.user.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;

    private final TokenRepository tokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final JwtService jwtService;

    private final AuthenticationManager authenticationManager;
    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();
        var savedUser = repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        // when to token is just created its not revoked or expired
        var refreshToken = jwtService.generateRefreshToken(user);
        saveUserToken(savedUser, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();

    }



    // when user clicks authenticate example 4 times then 4 tokens are saved in db for that user
    // all tokens are neither expired nor revoked means all are usable
    // we want to make it such a way that for one specific user i need to have maximum one valid usable token
    // rest of them need to be expired , revoked
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // at this point user is authenticated, means username and password are correct
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, jwtToken);
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();

    }

    private void revokeAllUserTokens(User user) {
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty())
            return;
        validUserTokens.forEach(t -> {
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    private void saveUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(HttpServletRequest request,
                             HttpServletResponse response) throws IOException {
        // check if we have Jwt token present or not in http request
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION); // pass the header name,
        // Authorization this header contains the Jwt token or the bearer token
        final String refreshToken;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        // take a substring of jwt from 7th index why 7 , Bearer  plus space adds up to 7
        refreshToken = authHeader.substring(7);
        // once extracted jwt token call user details service to check if user is there or not in database
        // but to do that we need to call JwtService to extract the user name
        userEmail = jwtService.extractUsername(refreshToken); // to do ectract the useremail from JWT token,
        // to do this i needa class that can manipulate JWT token thats jwt service, call it JWTdotextractUsername
        // SecurityContextHolder.getContext().getAuthentication() == null means user is not yet authenticated
        // means user is not connected yet
        if (userEmail != null) { // here you dont have to check again if user is authenticated or not
            // getting user from repository / database
            var user = this.repository.findByEmail(userEmail).orElseThrow(); // if u dont find user just throw exception
            // skip is token valid because we will not be validating the access token but we will be validating refresh token
            // jwtService.isTokenValid will juest check username with the username from object from db and expiration time of the passed token
            // jwtService.isTokenValid does not extract the token from repositiry and check the tokens status from reppository
            // now we r relying on the token itself and also relying on the database to check that token is already
            // in our database and its not expired and not revoked
            // next is magic use spring provided logout handler and logout success handler
            if (jwtService.isTokenValid(refreshToken, user)) { // if token valid we need to update securitycontext
                var accessToken = jwtService.generateToken(user);
                revokeAllUserTokens(user);
                saveUserToken(user, accessToken);
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                // from fasterxml.jackson
                // we want to write response value authResponse in output stream response.getOutputStream()
                // response.getOutputStream() body of response
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);

            }

        }
    }
}
