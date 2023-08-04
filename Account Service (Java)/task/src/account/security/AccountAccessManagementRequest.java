package account.security;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class AccountAccessManagementRequest {
    @JsonProperty("user")
    private String user;
    @JsonProperty("operation")
    String operation;
}
