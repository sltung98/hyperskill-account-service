package account.user;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class NewPassword {
    @JsonProperty("new_password")
    @NotBlank
    @Size(min = 12, message = "Password length must be 12 chars minimum!")
    @Pattern(regexp = "^(?!(PasswordForJanuary|PasswordForFebruary|PasswordForMarch|" +
            "PasswordForApril|PasswordForMay|PasswordForJune|PasswordForJuly|" +
            "PasswordForAugust|PasswordForSeptember|PasswordForOctober|" +
            "PasswordForNovember|PasswordForDecember)$).*$",
            message = "The password is in the hacker's database!")
    String newPassword;

}
