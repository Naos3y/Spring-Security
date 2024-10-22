package lopes.bruno.spring_security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

/**
 * User entity class that represents a user in the system.
 * This class implements UserDetails interface which is a core interface in Spring Security.
 *
 * UserDetails interface provides core user information to Spring Security, including:
 * - User credentials (username and password)
 * - User authorities/roles
 * - Account status (expired, locked, etc.)
 *
 * This implementation stores user data in a database table named "user".
 */
@Data  // Lombok: generates getters, setters, toString, equals, hashCode
@Builder  // Lombok: implements Builder pattern
@NoArgsConstructor  // Lombok: generates no-args constructor
@AllArgsConstructor  // Lombok: generates constructor with all args
@Entity  // JPA: marks this class as a database entity
@Table(name = "users")  // JPA: specifies the database table name
public class User implements UserDetails {

    @Id  // JPA: marks this field as the primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)  // JPA: auto-increment
    private long id;

    private String firstName;
    private String lastName;
    private String username;
    private String password;
    private String email;

    /**
     * User's role in the system.
     * Stored as a STRING in the database using JPA's EnumType.STRING
     */
    @Enumerated(EnumType.STRING)
    private Role role;

    /**
     * Returns the authorities granted to the user.
     * In this implementation, we convert the user's role to a SimpleGrantedAuthority.
     * This is used by Spring Security for authorization decisions.
     *
     * @return a list containing the user's role as a GrantedAuthority
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority(role.name()));
    }

    /**
     * Indicates whether the user's account has expired.
     * In this implementation, accounts never expire.
     *
     * @return true (always, indicating account is not expired)
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is locked or unlocked.
     * In this implementation, accounts are never locked.
     *
     * @return true (always, indicating account is not locked)
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * Indicates whether the user's credentials (password) has expired.
     * In this implementation, credentials never expire.
     *
     * @return true (always, indicating credentials are not expired)
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * Indicates whether the user is enabled or disabled.
     * In this implementation, users are always enabled.
     *
     * @return true (always, indicating user is enabled)
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}