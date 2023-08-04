package account.payment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;


@Service
public class PayrollService {
    PayrollRepository payrollRepository;

    @Autowired
    public PayrollService(PayrollRepository payrollRepository) {
        this.payrollRepository = payrollRepository;
    }

    public PayRoll save(PayRoll toSave) {
        return payrollRepository.save(toSave);
    }

    public Iterable<PayRoll> saveAll(List<PayRoll> toSave) {
        return payrollRepository.saveAll(toSave);
    }


    public Optional<Iterable<PayRoll>> findAllByEmployeeEmailIgnoreCase(String employeeEmail) {
        return payrollRepository.findAllByEmployeeEmailIgnoreCase(employeeEmail);
    }

    public boolean existsByEmployeeEmailAndPeriodIgnoreCase(String employeeEmail, String period) {
        return payrollRepository.existsByEmployeeEmailAndPeriodIgnoreCase(employeeEmail, period);
    }

    public Optional<PayRoll> findByEmployeeEmailAndPeriodIgnoreCase(String employeeEmail, String period) {
        return payrollRepository.findByEmployeeEmailAndPeriodIgnoreCase(employeeEmail, period);
    }


}