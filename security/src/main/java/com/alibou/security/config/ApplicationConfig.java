package com.alibou.security.config;

import com.alibou.security.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
// @Configurationmeans at startup spring will pickup this class and try to inject and implement all the beans in this class
@RequiredArgsConstructor
public class ApplicationConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        // as find by email returns optional we need orelse throw exception
        // lambda expression
        // loadUserByUsername(userEmail) is replaced by lambda expression instead of overriding
        return username -> userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // AuthenticationProvider its the data access object DAO which is responsible to fetch userdetails, and also encode password
    @Bean
    public AuthenticationProvider authenticationProvider() {
        // it has many implementattions one of them is DAO
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        // we need to tell authProvider which userdetails to use inorder to fetch information about
        // our user , we might have multiple implementations of userdetails
        // one for ex getting info from database another one based on a different profile from in memory database, ldap etc
        authProvider.setUserDetailsService(userDetailsService());
        // provide password encoder which we r using in our app
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() { // should be public
        return new BCryptPasswordEncoder();
    }
    // one more step authentication manager one responsible to manage authentication
    // it has bunch of methods and one of them helps authenticate user , using just username and password
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}
