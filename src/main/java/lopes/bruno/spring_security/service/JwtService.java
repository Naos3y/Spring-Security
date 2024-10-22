package lopes.bruno.spring_security.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import lopes.bruno.spring_security.config.JwtProperties;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

/**
 * Service class for handling JWT (JSON Web Token) operations.
 *
 * JWT Claims are pieces of information asserted about a subject. They are the payload
 * part of the JWT and contain the data we want to transmit securely. Claims can be:
 * - Registered claims: Predefined claims like 'sub' (subject), 'iat' (issued at), 'exp' (expiration)
 * - Public claims: Custom claims that are collision-resistant
 * - Private claims: Custom claims agreed upon by parties using them
 */
@Service
@RequiredArgsConstructor
public class JwtService {

    private final JwtProperties jwtProperties;

    /**
     * Generates a JWT token for a user without any extra claims.
     *
     * @param userDetails the user details
     * @return the generated JWT token
     */
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    /**
     * Generates a JWT token with extra claims.
     *
     * @param extraClaims additional claims to add to the token
     * @param userDetails the user details
     * @return the generated JWT token
     */
    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .claims(extraClaims)  // Add any additional claims
                .subject(userDetails.getUsername())  // Set the subject (username)
                .issuedAt(new Date(System.currentTimeMillis()))  // Set token creation time
                .expiration(new Date(System.currentTimeMillis() + jwtProperties.getExpiration()))  // Set token expiration
                .signWith(getSigningKey(), Jwts.SIG.HS256)  // Sign the token with HS256 algorithm
                .compact();  // Build the token
    }

    /**
     * Extracts the username from a token.
     *
     * @param token the JWT token
     * @return the username stored in the token
     */
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    /**
     * Generic method to extract a claim from a token.
     *
     * @param token the JWT token
     * @param claimsResolver function to extract the desired claim
     * @return the extracted claim value
     */
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = getAllClaimsFromToken(token);
        return claimsResolver.apply(claims);
    }

    /**
     * Extracts all claims from a token.
     *
     * @param token the JWT token
     * @return all claims stored in the token
     */
    private Claims getAllClaimsFromToken(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())  // Verify token signature
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    /**
     * Creates the signing key used to sign the JWT tokens.
     *
     * @return the signing key
     */
    private SecretKey getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtProperties.getSecretKey());
        return Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * Extracts the expiration date from a token.
     *
     * @param token the JWT token
     * @return the token's expiration date
     */
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    /**
     * Checks if a token has expired.
     *
     * @param token the JWT token
     * @return true if the token has expired, false otherwise
     */
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    /**
     * Validates a token for a specific user.
     * Checks both username match and token expiration.
     *
     * @param token the JWT token
     * @param userDetails the user details
     * @return true if the token is valid for the user, false otherwise
     */
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String extractedUsername = extractUsername(token);
        return (extractedUsername.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }
}