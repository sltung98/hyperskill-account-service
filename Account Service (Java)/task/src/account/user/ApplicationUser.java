package account.user;

import account.security.ApplicationUserRole;
import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@Table(name = "application_users")
public class ApplicationUser implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "user_id")
    private long id;
    @NotBlank
    @Column(name = "name")
    @JsonProperty("name")
    private String name;
    @NotBlank
    @Column(name = "last_name")
    @JsonProperty("lastname")
    private String lastName;
    @NotBlank
    @Pattern(regexp = "\\S+@acme.com")
    @Column(name = "email")
    private String email;
    @NotBlank
    @Column(name = "password")
    @Size(min = 12, message = "The password length must be at least 12 chars!")
    @Pattern(regexp = "^(?!(PasswordForJanuary|PasswordForFebruary|PasswordForMarch|" +
            "PasswordForApril|PasswordForMay|PasswordForJune|PasswordForJuly|" +
            "PasswordForAugust|PasswordForSeptember|PasswordForOctober|" +
            "PasswordForNovember|PasswordForDecember)$).*$",
            message = "The password is in the hacker's database!")
    private String password;

    private boolean accountNonExpired;

    private boolean accountNonLocked;

    private boolean credentialsNonExpired;

    private boolean enabled;

    @Column(name = "failed_attempt")
    private int failedAttempt;

    @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<ApplicationUserRole> grantedAuthorities = new HashSet<>();

    @Column(name = "is_admin")
    private boolean isAdmin;

    public ApplicationUser() {
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
        this.enabled = true;
        this.isAdmin = false;
        this.failedAttempt = 0;
    }


    @Override
    public String getUsername() {
        return email;
    }


    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return grantedAuthorities;
    }

    public void addAuthorities(ApplicationUserRole authority) {
        grantedAuthorities.add(authority);
    }

    public void deleteAuthorities(ApplicationUserRole authority) {
        grantedAuthorities.remove(authority);
    }
}
