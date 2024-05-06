package com.sau.jwt.security;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.LogoutConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final UserDetailsServiceDAO userDetailsService;
    private final JwtUtility jwtUtility;


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.addFilterBefore(new AuthTokenFilter(userDetailsService,jwtUtility), UsernamePasswordAuthenticationFilter.class);
        http.authorizeHttpRequests(auth->auth
                        .requestMatchers("/user").hasAnyRole("USER", "ADMIN")
                        .requestMatchers("/admin").hasRole("ADMIN")
                        .requestMatchers("/", "/login").permitAll()
                        .anyRequest().authenticated())
                        .csrf(AbstractHttpConfigurer::disable)
                        .sessionManagement(session-> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                        .logout(LogoutConfigurer::permitAll);
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    @Bean
    AuthenticationManager authenticationProviderBean(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
