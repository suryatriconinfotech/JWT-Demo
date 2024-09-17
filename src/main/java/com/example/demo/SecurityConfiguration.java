package com.example.demo;


import com.example.demo.webtoken.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {


    @Autowired
    @Lazy
    JwtAuthenticationFilter jwtAuthenticationFilter;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
       return httpSecurity
               .csrf(AbstractHttpConfigurer::disable)
               .authorizeHttpRequests(r->{
           r.requestMatchers("/home").permitAll();
           r.requestMatchers("/register/**","/authenticate").permitAll();
           r.requestMatchers("/admin/**").hasRole("ADMIN");
           r.requestMatchers("/user/**").hasRole("USER");
           r.anyRequest().authenticated();
       })

               .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
               .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
               .build();
    }

   @Bean
    public UserDetailsService userDetailsService(){
       UserDetails userDetails= User.builder()
               .username("user")
               .password("$2a$12$qvCEuMzDplFiprKVoE/ctuAZssB2k5WpJZ02HC/bht7oBd/bQyhIW")
               .roles("USER")
               .build();
       UserDetails adminDetails= User.builder()
               .username("admin")
               .password("$2a$12$qvCEuMzDplFiprKVoE/ctuAZssB2k5WpJZ02HC/bht7oBd/bQyhIW")
               .roles("ADMIN","USER")
               .build();
       return new InMemoryUserDetailsManager(userDetails,adminDetails);
   }

   @Bean
   public AuthenticationProvider authenticationProvider(){
       DaoAuthenticationProvider provider=new DaoAuthenticationProvider();
       provider.setPasswordEncoder(passwordEncoder());
       provider.setUserDetailsService(userDetailsService());

       return provider;
   }
   @Bean
   public AuthenticationManager authenticationManager(){
        return new ProviderManager(authenticationProvider());
   }

   @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
   }
}
