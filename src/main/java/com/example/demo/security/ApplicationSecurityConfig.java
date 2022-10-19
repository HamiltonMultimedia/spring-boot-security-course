package com.example.demo.security;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static com.example.demo.security.ApplicationUserPermission.COURSE_WRITE;
import static com.example.demo.security.ApplicationUserRole.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

        private final PasswordEncoder passwordEncoder;

        @Autowired
        public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
            this.passwordEncoder = passwordEncoder;
        }
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails tanyaUser = User.builder()
                .username("tanya")
                .password(passwordEncoder.encode("password"))
<<<<<<< HEAD
                .roles(STUDENT.name()) // ROLE_STUDENT
=======
//                .roles(STUDENT.name()) // ROLE_STUDENT
>>>>>>> a368e71 (Restored Missing Branches)
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails terenceUser = User.builder()
                .username("terence")
                .password(passwordEncoder.encode("password123"))
<<<<<<< HEAD
                .roles(ADMIN.name()) // ROLE_ADMIN
=======
//                .roles(ADMIN.name()) // ROLE_ADMIN
>>>>>>> a368e71 (Restored Missing Branches)
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails patrickUser = User.builder()
                .username("patrick")
                .password(passwordEncoder.encode("password456"))
<<<<<<< HEAD
                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
=======
//                .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE
>>>>>>> a368e71 (Restored Missing Branches)
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                tanyaUser,
                terenceUser,
                patrickUser
        );

    }

    private static HttpSecurity getHttp(HttpSecurity http) {
        return http;
    }
}
