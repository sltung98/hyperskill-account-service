package account.security;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import java.util.Objects;

@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
public class ApplicationUserRole implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "role_id")
    private long id;

    @Column(name = "role_name")
    @Enumerated(EnumType.ORDINAL)
    private ApplicationUserRoleEnum role;

    public ApplicationUserRole(ApplicationUserRoleEnum role) {
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return "ROLE_" + this.role.name();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApplicationUserRole that = (ApplicationUserRole) o;
        return role == that.role;
    }

    @Override
    public int hashCode() {
        return Objects.hash(role);
    }
}
