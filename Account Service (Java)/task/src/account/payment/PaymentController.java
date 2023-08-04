package account.payment;

import account.exception.PayrollNotFoundException;
import account.exception.RedundantPayrollException;
import account.user.ApplicationUser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("api/")
@Transactional
public class PaymentController {
    ObjectMapper objectMapper;
    PayrollService payrollService;
    BCryptPasswordEncoder passwordEncoder;
    private static final Logger LOGGER = LoggerFactory.getLogger(PaymentController.class);

    @Autowired
    public PaymentController(ObjectMapper objectMapper, PayrollService payrollService, BCryptPasswordEncoder passwordEncoder) {
        this.objectMapper = objectMapper;
        this.payrollService = payrollService;
        this.passwordEncoder = passwordEncoder;
    }


    @PostMapping(path = "acct/payments", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ACCOUNTANT')")
    public ResponseEntity uploadPayrolls(@RequestBody(required = false) List<@Valid PayRoll> payRolls) throws JsonProcessingException {
        Set<String> set = new HashSet<>();
        payRolls.stream()
                .map(payRoll -> payRoll.getPeriod() + payRoll.getEmployeeEmail())
                .toList()
                .forEach(s -> {
                    if (!set.add(s)) {
                        throw new RedundantPayrollException();
                    }
                });

        payRolls.stream()
                .forEach(payRoll -> {
                    if (payrollService.existsByEmployeeEmailAndPeriodIgnoreCase(payRoll.getEmployeeEmail(), payRoll.getPeriod())) {
                        throw new RedundantPayrollException();
                    }
                });

        payrollService.saveAll(payRolls);
        return new ResponseEntity(
                objectMapper.writeValueAsString(
                        Map.of("status", "Added successfully!")
                ), HttpStatus.OK
        );
    }

    @PutMapping(path = "acct/payments", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ACCOUNTANT')")
    public ResponseEntity updatePayroll(@RequestBody(required = false) @Valid PayRoll payRoll) throws JsonProcessingException {

        String employeeEmail = payRoll.getEmployeeEmail();
        String period = payRoll.getPeriod();
        if (!payrollService.existsByEmployeeEmailAndPeriodIgnoreCase(employeeEmail, period)) {
            throw new PayrollNotFoundException();
        } else {
            Optional<PayRoll> payRollFound = payrollService.findByEmployeeEmailAndPeriodIgnoreCase(employeeEmail, period);
            payRollFound.get().setSalary(payRoll.getSalary());
            payrollService.save(payRollFound.get());
            return new ResponseEntity(
                    objectMapper.writeValueAsString(
                            Map.of("status", "Updated successfully!")
                    ), HttpStatus.OK
            );
        }

    }


    @GetMapping(path = "empl/payment", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ACCOUNTANT')")
    public ResponseEntity getPayrolls(@AuthenticationPrincipal ApplicationUser userDetails,
                                      @RequestParam(required = false, name = "period") String period) throws JsonProcessingException {
        String name = userDetails.getName();
        String lastName = userDetails.getLastName();


        if (period == null) {
            Optional<Iterable<PayRoll>> payrolls;
            Deque<Map<String, String>> body = new ArrayDeque<>();
            payrolls = payrollService.findAllByEmployeeEmailIgnoreCase(userDetails.getEmail());
            if (payrolls.isPresent()) {
                payrolls.get().forEach(payRoll -> {
                    body.offerFirst(
                            Map.of("name", name,
                                    "lastname", lastName,
                                    "period", payRoll.getFormattedPeriod(),
                                    "salary", payRoll.getFormattedSalary())
                    );
                });
                return new ResponseEntity(
                        objectMapper.writeValueAsString(body),
                        HttpStatus.OK
                );
            } else {
                throw new PayrollNotFoundException();
            }
        } else {
            Optional<PayRoll> payrollFound = payrollService.findByEmployeeEmailAndPeriodIgnoreCase(userDetails.getEmail(), period);
            Map<String, String> body = new HashMap<>();
            if (payrollFound.isPresent()) {
                body = Map.of("name", name,
                        "lastname", lastName,
                        "period", payrollFound.get().getFormattedPeriod(),
                        "salary", payrollFound.get().getFormattedSalary());
                return new ResponseEntity(
                        objectMapper.writeValueAsString(body),
                        HttpStatus.OK
                );
            } else {
                throw new PayrollNotFoundException();
            }

        }

    }
}
