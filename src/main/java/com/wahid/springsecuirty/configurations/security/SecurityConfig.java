package com.wahid.springsecuirty.configurations.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)requests.anyRequest()).authenticated();
        });
        //http.formLogin(Customizer.withDefaults());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.httpBasic(Customizer.withDefaults());
        return (SecurityFilterChain)http.build();
    }

    @Bean
    public UserDetailsService userDetailsService()
    {
        // creating userDetails objects
        UserDetails user1 = User.withUsername("user1")
                .password("{noop}1234") //
                .roles("USER")
                .build();
        UserDetails user2 = User.withUsername("user2")
                .password("{noop}1234") //
                .roles("USER")
                .build();
        UserDetails admin = User.withUsername("admin")
                .password("{noop}1234") //
                .roles("ADMIN")
                .build();
        return new InMemoryUserDetailsManager(user1,user2, admin);
        // this will users credentials and roles in user details object
    }
}
