package account.security;

import account.user.ApplicationUser;
import account.user.UserService;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationEvents {
    UserService userService;
    public AuthenticationEvents(UserService userService) {
        this.userService = userService;
    }
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent successEvent) {
        String email = successEvent.getAuthentication().getName();
        ApplicationUser user = userService.loadUserByUsername(email);
        if (!user.isAdmin()) {
            userService.resetFailedAttempts(user);
        }
    }

}