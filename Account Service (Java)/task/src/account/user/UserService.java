package account.user;

import account.exception.UserNotFoundException;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Transactional
public class UserService implements UserDetailsService {

    public static final int MAX_FAILED_ATTEMPTS = 5;
    @Autowired
    UserRepository userRepository;
    @Autowired
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public ApplicationUser loadUserByUsername(String s) throws UsernameNotFoundException {
        Optional<ApplicationUser> user = userRepository.findByEmailIgnoreCase(s);

        if (user.isPresent()) {
            return user.get();
        } else {
            throw new UserNotFoundException();
        }
    }

    public boolean existsByUsername(String s) {
        return userRepository.existsByEmailIgnoreCase(s);
    }
    public void deleteUser(ApplicationUser toDelete) {userRepository.delete(toDelete);}

    public Iterable<ApplicationUser> findAll() {return userRepository.findAll(); }
    public ApplicationUser save(ApplicationUser toSave) {
        return userRepository.save(toSave);
    }

    public boolean isAdminExists() {
        return userRepository.existsByIsAdmin(true);
    };

    public void increaseFailedAttempts(ApplicationUser user) {
        user.setFailedAttempt(user.getFailedAttempt() + 1);
        userRepository.save(user);
    }

    public void resetFailedAttempts(ApplicationUser user) {
        user.setFailedAttempt(0);
        userRepository.save(user);
    }

    public void lock(ApplicationUser user) {
        user.setAccountNonLocked(false);
        userRepository.save(user);
    }

    public void unlock(ApplicationUser user) {
        user.setAccountNonLocked(true);
        user.setFailedAttempt(0);
        userRepository.save(user);
    }

}
