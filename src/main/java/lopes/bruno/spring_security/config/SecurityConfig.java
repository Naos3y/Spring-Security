package lopes.bruno.spring_security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration  // Indicates that this is a configuration class
@EnableWebSecurity  // Enables Spring Security's web security support
@RequiredArgsConstructor  // Lombok annotation to create constructor for final fields
public class SecurityConfig {

    // Injectable authentication provider that handles the authentication logic
    private final AuthenticationProvider authenticationProvider;

    /**
     * Configures the security filter chain for the application.
     * This method defines:
     * - Which endpoints are public/private
     * - CSRF settings
     * - Session management
     * - Authentication setup
     *
     * @param http The HttpSecurity object to configure
     * @param jwtAuthFilter The JWT authentication filter to be added to the chain
     * @return Configured SecurityFilterChain
     */
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthFilter jwtAuthFilter  // Updated naming for clarity
    ) throws Exception {
        return http
                // Disable CSRF protection as we're using JWT tokens
                .csrf(csrf -> csrf.disable())

                // Configure authorization rules
                .authorizeHttpRequests(auth -> auth
                        // Public endpoints (add your public endpoints here)
                        .requestMatchers(
                                "/api/v1/auth/**"
                        ).permitAll()
                        // All other endpoints require authentication
                        .anyRequest().authenticated()
                )

                // Configure session management
                .sessionManagement(session -> session
                        // Don't create sessions - we're using JWT tokens
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // Configure authentication
                .authenticationProvider(authenticationProvider)

                // Add JWT filter before the standard authentication filter
                .addFilterBefore(
                        jwtAuthFilter,
                        UsernamePasswordAuthenticationFilter.class
                )

                // Build the configuration
                .build();
    }
}
