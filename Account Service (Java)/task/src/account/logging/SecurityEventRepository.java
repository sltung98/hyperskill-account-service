package account.logging;

import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface SecurityEventRepository extends CrudRepository<SecurityEvent, Long> {

}