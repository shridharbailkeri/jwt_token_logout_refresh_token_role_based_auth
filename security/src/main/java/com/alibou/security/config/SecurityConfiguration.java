package com.alibou.security.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import static com.alibou.security.user.Permission.*;
import static com.alibou.security.user.Role.ADMIN;
import static com.alibou.security.user.Role.MANAGER;
import static org.springframework.http.HttpMethod.*;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableMethodSecurity
public class SecurityConfiguration {
    // final, so it will be automaticallly injected by spring
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;
    //@Configuration and @EnableWebSecurity needs to be together when we work with spring boot 3.0

    // whole process(jwtauthfilter, validatejwt, jwtservice) is implemented but we need to tell spring
    // which configuration to use in order make all these things work  -> for binding we need to bind
    // we created filter but its not yet used

    // at application start up spring security will try to look for bean of type security filter chain
    // and this is the bean responsible for configuring all http security of our application

    private final LogoutHandler logoutHandler;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http
                .csrf()
                .disable()
                .authorizeHttpRequests()
                .requestMatchers("/api/v1/auth/**")
                .permitAll()
                // first we secure the management endpoint that should be only accessible by Admin and Manager roles
                .requestMatchers("/api/v1/management/**").hasAnyRole(ADMIN.name(), MANAGER.name())
                //GET rember its actually HttpMethod.GET static import is made so u only see GET
                // this endpoint "/api/v1/management/**" is only accesible by people having following authorities
                // now I am securing the different operations get its only by admin and manager , so on and so forth
                .requestMatchers(GET, "/api/v1/management/**").hasAnyAuthority(ADMIN_READ.name(), MANAGER_READ.name())
                .requestMatchers(POST, "/api/v1/management/**").hasAnyAuthority(ADMIN_CREATE.name(), MANAGER_CREATE.name())
                .requestMatchers(PUT, "/api/v1/management/**").hasAnyAuthority(ADMIN_UPDATE.name(), MANAGER_UPDATE.name())
                .requestMatchers(DELETE, "/api/v1/management/**").hasAnyAuthority(ADMIN_DELETE.name(), MANAGER_DELETE.name())

 /*               .requestMatchers("/api/v1/admin/**").hasRole(ADMIN.name())
                // so for admin endpoint the diff resources are accessible only to admin
                .requestMatchers(GET, "/api/v1/admin/**").hasAuthority(ADMIN_READ.name())
                .requestMatchers(POST, "/api/v1/admin/**").hasAuthority(ADMIN_CREATE.name())
                .requestMatchers(PUT, "/api/v1/admin/**").hasAuthority(ADMIN_UPDATE.name())
                .requestMatchers(DELETE, "/api/v1/admin/**").hasAuthority(ADMIN_DELETE.name())*/

                .anyRequest()
                .authenticated()
                .and() // configure session managemenet, when we implement filter we want once per request filter,
                // means we should not store the authentication state, or session state should not be stored, session should be stateless
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // spring will create new session for each request
                .and() // which authentication provider i need to use
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) // Before() means add execute filter before UsernamePasswordAuthentication filter
                //The method addFilterBefore is used to add a new filter (jwtAuthFilter) before a specific filter (UsernamePasswordAuthenticationFilter.class) in the filter chain.
                //the JWT authentication logic can be executed before the standard username and password authentication is performed.
                // first we update security context holder and after that we will be calling user name password auth filter
                .logout()
                // handler is a place where we keep all logout mechanism , spring uses default url /logout for logout, u can customize it
                .logoutUrl("/api/v1/auth/logout")
                // we habe our oAuth controller which contains our registration and authentication now I will have to add logout
                // but i will add just url and will tell spring, everytime u get request for this specific url, just implement the below logout handler
                .addLogoutHandler(logoutHandler)
                .logoutSuccessHandler(((request, response, authentication) ->
                        SecurityContextHolder.clearContext()));
                // once logout is successfull clear our security context
                // so if the user is logged out we need to clear security context in order to user cannot access again
                // this expired token he will not be able to access again our api




        return http.build();
    }
}
