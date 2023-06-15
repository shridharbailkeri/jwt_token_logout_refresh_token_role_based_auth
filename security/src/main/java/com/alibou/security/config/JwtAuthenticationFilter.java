package com.alibou.security.config;

import com.alibou.security.token.TokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
// to tell spring that its a managed bean to become spring bean, service or component or repository annotations work
// because three of them are same annotations
@Component
@RequiredArgsConstructor // uses any final field example private final string
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    // its an interface in spring security core frame work
    // to fetch our user from the database
    private final UserDetailsService userDetailsService;

    private final TokenRepository tokenRepository;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {
        //HttpServletRequest  its our request
        //HttpServletResponse its our response , we can intercept every request and make extract data from request
        // and provide new data for the response for example to add header to my response we can do it using OncePerRequestFilter
        //FilterChain is the chain of responsibility design pattern it contains list of other filters that we need to execute

        // check if we have Jwt token present or not in http request
        final String authHeader = request.getHeader("Authorization"); // pass the header name,
        // Authorization this header contains the Jwt token or the bearer token
        final String jwt;
        final String userEmail;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // if jwt token not present then call filter chain
            // do filter and pass request and response to the next filter
            filterChain.doFilter(request, response);
            return;
        }
        // take a substring of jwt from 7th index why 7 , Bearer  plus space adds up to 7
        jwt = authHeader.substring(7);
        // once extracted jwt token call user details service to check if user is there or not in database
        // but to do that we need to call JwtService to extract the user name
        userEmail = jwtService.extractUsername(jwt); // to do ectract the useremail from JWT token,
        // to do this i needa class that can manipulate JWT token thats jwt service, call it JWTdotextractUsername
        // SecurityContextHolder.getContext().getAuthentication() == null means user is not yet authenticated
        // means user is not connected yet
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // getting user from repository / database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);
            // check token is valid from database side
            // find a token then map isTokenValid var to a boolean to true if !t.isExpired()!t.isRevoked()
            var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);
            // jwtService.isTokenValid will juest check username with the username from object from db and expiration time of the passed token
            // jwtService.isTokenValid does not extract the token from repositiry and check the tokens status from reppository
            // now we r relying on the token itself and also relying on the database to check that token is already
            // in our database and its not expired and not revoked
            // next is magic use spring provided logout handler and logout success handler
            if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) { // if token valid we need to update securitycontext
                // and send the request to our dispatcher servlet
                // now need an object of type UsernamePasswordAuthenticationToken, its required by spring and security context holder
                // in order to update security context
                // we dont have credentials in this example
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                // once authToken object i want also to give it some more details, this takes in a object
                // build it based on details of our http request
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                // update security context holder, update authToken
                SecurityContextHolder.getContext().setAuthentication(authToken);

            }

        }
        // we always need to pass the hand to the next filter
        filterChain.doFilter(request, response);

    }
}
