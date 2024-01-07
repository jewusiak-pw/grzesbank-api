package pl.jewusiak.grzesbankapi.model.domain;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import pl.jewusiak.grzesbankapi.utils.ValidationService;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "users_table")
public class User implements UserDetails {
    
    @Id
    @Email
    private String email;
    private String firstName;
    private String lastName;
    
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<PasswordCombination> passwordCombinations;
    
    @Embedded
    private Address address;
    
    private LocalDateTime loginLockTime;
    
    @OneToOne(mappedBy = "owner", cascade = CascadeType.ALL)
    private Account account;
    
    @Embedded
    private SensitiveUserData sensitiveUserData;
    
    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    private CreditCard creditCard;
    
    
    public boolean isLoginLocked() {
        return loginLockTime != null && loginLockTime.isAfter(LocalDateTime.now());
    } 
    
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("user"));
    }

    @Override
    public String getPassword() {
        throw new UnsupportedOperationException("Standard password is not used in this application");
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isLoginLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
    
    @Embeddable
    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Address {
        
        @Pattern(regexp = ValidationService.plTextboxRegex)
        private String street;
        @Pattern(regexp = ValidationService.plTextboxRegex)
        private String city;
        @Pattern(regexp = ValidationService.plZipCodeRegex)
        private String zipCode;

        @Override
        public String toString() {
            return street+", "+city+", "+zipCode;
        }
    }

    @Override
    public String toString() {
        return "User{" +
                "email='" + email + '\'' +
                '}';
    }
}
