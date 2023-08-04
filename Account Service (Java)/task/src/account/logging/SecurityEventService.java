package account.logging;

import account.exception.UserNotFoundException;
import account.user.ApplicationUser;
import account.user.UserRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;
@Service
@Transactional
public class SecurityEventService {
    SecurityEventRepository securityEventRepository;

    @Autowired
    public SecurityEventService(SecurityEventRepository securityEventRepository) {
        this.securityEventRepository = securityEventRepository;
    }

    public Iterable<SecurityEvent> findAll() {
        return securityEventRepository.findAll();
    }
    public SecurityEvent save(SecurityEvent toSave) {
        return securityEventRepository.save(toSave);
    }

}