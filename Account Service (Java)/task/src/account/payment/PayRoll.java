package account.payment;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.PositiveOrZero;
import lombok.Data;

import java.time.Month;

@Data
@Entity
@Table(name = "payroll")
public class PayRoll {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long id;

    @NotBlank
    @Pattern(regexp = "\\S+@acme.com")
    @JsonProperty("employee")
    @Column(name = "employee")
    private String employeeEmail;

    @NotBlank
    @Pattern(regexp = "(0[1-9]|1[1-2])-\\d{4}", message = "Invalid period format.")
    @JsonProperty("period")
    @Column(name = "period")
    private String period;

    @PositiveOrZero(message = "salary cannot be negative.")
    @JsonProperty("salary")
    @Column(name = "salary")
    private long salary;

    public String getFormattedPeriod() {
        if (period != null) {
            String year = period.substring(period.length() - 4);
            String month = Month.of(Integer.parseInt(period.substring(0, period.length() - 5)))
                    .toString();
            month = month.charAt(0) + month.substring(1).toLowerCase();
            return month + "-" + year;
        }
        return "";
    }

    public String getFormattedSalary() {
        String salaryString;
            salaryString = String.valueOf(salary);
            if (salaryString.length() <= 2) {
                return "0 dollar(s) " + salaryString + " cent(s)";
            } else {
                return salaryString.substring(0, salaryString.length() - 2) +
                        " dollar(s) " +
                        salaryString.substring(salaryString.length() - 2) +
                        " cent(s)";
            }


    }

}
