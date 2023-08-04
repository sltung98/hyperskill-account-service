package account.user;

import account.exception.PasswordExistException;
import account.exception.UserExistException;
import account.logging.SecurityEvent;
import account.logging.SecurityEventNameEnum;
import account.logging.SecurityEventService;
import account.security.ApplicationUserRole;
import account.security.ApplicationUserRoleEnum;
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
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;

import java.time.LocalDateTime;
import java.util.*;
@Transactional
@RestController
@RequestMapping("api/auth/")
public class UserController {
    ObjectMapper objectMapper;
    UserService userService;
    SecurityEventService securityEventService;
    BCryptPasswordEncoder passwordEncoder;
    private static final Logger LOGGER = LoggerFactory.getLogger(UserController.class);

    @Autowired
    public UserController(ObjectMapper objectMapper, UserService userService,
                          BCryptPasswordEncoder passwordEncoder, SecurityEventService securityEventService) {
        this.objectMapper = objectMapper;
        this.userService = userService;
        this.securityEventService = securityEventService;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping(path = "changepass", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasAnyRole('ROLE_USER', 'ROLE_ACCOUNTANT', 'ROLE_ADMINISTRATOR')")
    public ResponseEntity changePassword(@AuthenticationPrincipal ApplicationUser userDetails,
                                         @Valid @RequestBody NewPassword newPassword,
                                         WebRequest request) throws JsonProcessingException {
        if (userService.existsByUsername(userDetails.getEmail())) {
            String email = userDetails.getEmail();
            String password = newPassword.getNewPassword();
            if (userService.existsByUsername(email) &&
                    !passwordEncoder.matches(password, userDetails.getPassword())) {
                ApplicationUser user = userService.loadUserByUsername(email);
                user.setPassword(passwordEncoder.encode(password));
                userService.save(user);

                SecurityEvent securityEvent = new SecurityEvent
                        (LocalDateTime.now(), SecurityEventNameEnum.CHANGE_PASSWORD,
                                email, email, request.getDescription(false).replaceAll("uri=", ""));
                securityEventService.save(securityEvent);
                LOGGER.info(securityEvent.toString());

                return new ResponseEntity(
                        objectMapper.writeValueAsString(
                                Map.of("email", user.getEmail(),
                                        "status", "The password has been updated successfully")
                        ), HttpStatus.OK
                );
            } else {
                throw new PasswordExistException();
            }
        } else {
            throw new UserExistException();
        }
    }

    @PostMapping(path = "signup", produces = "application/json")
    @ResponseBody
    public ResponseEntity signUp(@Valid @RequestBody ApplicationUser applicationUser,
                                 WebRequest request) throws JsonProcessingException {
        String email = applicationUser.getEmail().toLowerCase();
        if (!userService.existsByUsername(email)) {
            applicationUser.setEmail(email);
            applicationUser.setPassword(passwordEncoder.encode(applicationUser.getPassword()));
            ApplicationUserRole role;
            if (userService.isAdminExists()) {
                role = new ApplicationUserRole(ApplicationUserRoleEnum.USER);
                applicationUser.setAdmin(false);
            } else {
                role = new ApplicationUserRole(ApplicationUserRoleEnum.ADMINISTRATOR);
                applicationUser.setAdmin(true);
            }

            applicationUser.addAuthorities(role);
            userService.save(applicationUser);

            SecurityEvent securityEvent = new SecurityEvent(
                    LocalDateTime.now(), SecurityEventNameEnum.CREATE_USER,
                    "Anonymous", email, request.getDescription(false).replaceAll("uri=", "")
            );
            securityEventService.save(securityEvent);
            LOGGER.info(securityEvent.toString());

            return new ResponseEntity(
                    objectMapper.writeValueAsString(
                            Map.of("id", applicationUser.getId(),
                                    "name", applicationUser.getName(),
                                    "lastname", applicationUser.getLastName(),
                                    "email", email,
                                    "roles", applicationUser.getAuthorities().stream()
                                            .map(GrantedAuthority::getAuthority))
                    ), HttpStatus.OK
            );
        } else {
            throw new UserExistException();
        }

    }




}
