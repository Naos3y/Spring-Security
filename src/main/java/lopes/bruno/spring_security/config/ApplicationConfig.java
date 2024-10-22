package lopes.bruno.spring_security.config;

import lombok.RequiredArgsConstructor;
import lopes.bruno.spring_security.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Application configuration class that provides core beans for the application.
 * This class is responsible for configuring and providing user-related services
 * and security components.
 *
 * The @Configuration annotation indicates that this class contains Spring bean definitions
 * and may be processed by the Spring container to generate bean definitions and service
 * requests for those beans at runtime.
 */
@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

    // Repository for user-related database operations
    private final UserRepository userRepository;

    /**
     * Creates and configures the UserDetailsService bean.
     * UserDetailsService is a core interface in Spring Security framework that is used to retrieve
     * user-related data. It has one method that loads user details by username.
     *
     * In this implementation, the username is actually the user's email address.
     * The method will attempt to find a user by their email in the database.
     * If no user is found, it throws a UsernameNotFoundException.
     *
     * @return A UserDetailsService implementation that fetches user data from the repository
     * @throws UsernameNotFoundException if no user is found with the given email
     */
    @Bean
    public UserDetailsService userDetailsService(){
        // Using lambda expression to implement the loadUserByUsername method
        return username -> userRepository.findByEmail(username)
                .orElseThrow(
                        // Throw exception if user not found
                        () -> new UsernameNotFoundException("User not found")
                );
    }

    @Bean
    public AuthenticationProvider authenticationProvider(){
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}