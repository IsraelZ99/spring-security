package com.example.security.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;

    /**
     * Basic authentication (with username and password in headers)
     **/
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic(); // Basic authentication.
    }

    @Override
    @Bean
    /** User in memory with encrypt password (Class PasswordConfig to set the type of encode). **/
    protected UserDetailsService userDetailsService() {
        UserDetails israelUser = User.builder()
                .username("israel.garcia")
                .password(passwordEncoder.encode("password"))
                .roles("STUDENT") //ROLE_STUDENT
                .build();

        UserDetails monseUser = User.builder()
                .username("monserrat")
                .password(passwordEncoder.encode("12345"))
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(
                israelUser
        );
    }
}
