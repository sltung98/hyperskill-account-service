package account.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class RoleManagementRequest {

    @JsonProperty("user")
    private String email;

    @JsonProperty("role")
    private String role;

    @JsonProperty("operation")
    private String operation;

}
