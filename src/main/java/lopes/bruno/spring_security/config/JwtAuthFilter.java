package lopes.bruno.spring_security.config;

import io.micrometer.common.lang.NonNull;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lopes.bruno.spring_security.service.JwtService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter Purpose: It intercepts every HTTP request to check for and validate JWT tokens.
 *
 * JWT Authentication Filter that processes and validates JWT tokens for each HTTP request.
 * This filter extends OncePerRequestFilter to guarantee it is executed only once per request.
 *
 * The filter checks for the presence of a JWT token in the Authorization header,
 * validates it, and sets up the security context if the token is valid.
 */
@Component
@RequiredArgsConstructor  // Lombok annotation to create constructor for final fields
public class JwtAuthFilter extends OncePerRequestFilter {

    // Service for JWT operations like token validation and username extraction
    private final JwtService jwtService;

    // Service to load user details from the database
    private final UserDetailsService userDetailsService;

    /**
     * Core method that processes each HTTP request to validate JWT tokens and set up security context.
     *
     * @param request The HTTP request
     * @param response The HTTP response
     * @param filterChain The filter chain for passing the request to the next filter
     * @throws ServletException If there's an error in the servlet
     * @throws IOException If there's an I/O error
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        // Extract the Authorization header from the request
        final String authHeader = request.getHeader("Authorization");
        final String token;
        final String username;

        // If Authorization header is missing or doesn't start with "Bearer ", proceed to next filter
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request, response);
            return; // Add return statement to prevent further execution
        }

        // Extract the token (remove "Bearer " prefix)
        token = authHeader.substring(7); // "Bearer " is 7 characters

        // Extract username from the token using JwtService
        username = jwtService.extractUsername(token);

        // Process the token if username exists and no authentication is set in SecurityContext
        if(username != null && SecurityContextHolder.getContext().getAuthentication() == null){
            // Load user details from database
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);

            // Validate the token
            if(jwtService.isTokenValid(token, userDetails)){
                // Create authentication token
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails,      // Principal (user details)
                        null,            // Credentials (null as we don't need password after authentication)
                        userDetails.getAuthorities()  // User authorities/roles
                );

                // Add request details to authentication token
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Set the authentication in the SecurityContext
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // Proceed with the filter chain
        filterChain.doFilter(request, response);
    }
}