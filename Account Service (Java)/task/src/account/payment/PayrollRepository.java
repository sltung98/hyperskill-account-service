package account.payment;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PayrollRepository extends CrudRepository<PayRoll, Long> {

    Optional<PayRoll> findByEmployeeEmailAndPeriodIgnoreCase(String employeeEmail, String period);
    Optional<Iterable<PayRoll>> findAllByEmployeeEmailIgnoreCase(String employeeEmail);

    boolean existsByEmployeeEmailAndPeriodIgnoreCase(String employeeEmail, String period);

}