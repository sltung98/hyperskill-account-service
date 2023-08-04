package account.user;

import account.exception.*;
import account.logging.SecurityEvent;
import account.logging.SecurityEventNameEnum;
import account.logging.SecurityEventService;
import account.security.AccountAccessManagementRequest;
import account.security.ApplicationUserRole;
import account.security.ApplicationUserRoleEnum;
import account.security.RoleManagementRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.Pattern;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDateTime;
import java.util.*;

@RestController
@RequestMapping("api/admin")
public class AdminController {
    ObjectMapper objectMapper;
    UserService userService;
    SecurityEventService securityEventService;
    BCryptPasswordEncoder passwordEncoder;
    private static final Logger LOGGER = LoggerFactory.getLogger(AdminController.class);

    @Autowired
    public AdminController(ObjectMapper objectMapper, UserService userService,
                           BCryptPasswordEncoder passwordEncoder, SecurityEventService securityEventService) {
        this.objectMapper = objectMapper;
        this.securityEventService = securityEventService;
        this.userService = userService;
        this.passwordEncoder = passwordEncoder;
    }

    @DeleteMapping(path = "/user/{userEmail}", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity deleteUsers(WebRequest request,
                                      @AuthenticationPrincipal ApplicationUser userDetails,
                                      @PathVariable(name = "userEmail") @Pattern(regexp = "\\S+@acme.com") String userEmail) throws JsonProcessingException {
        ApplicationUser userFound = userService.loadUserByUsername(userEmail);
        if (userFound == null) {
            throw new UserNotFoundException();
        } else if (userFound.isAdmin()) {
            throw new DeleteAdminException();
        } else {
            userService.deleteUser(userFound);

            SecurityEvent securityEvent = new SecurityEvent(LocalDateTime.now(), SecurityEventNameEnum.DELETE_USER,
                    userDetails.getEmail(), userEmail, request.getDescription(false).replaceAll("uri=", ""));
            securityEventService.save(securityEvent);
            LOGGER.info(securityEvent.toString());

            return new ResponseEntity(
                    objectMapper.writeValueAsString(
                            Map.of("user", userFound.getEmail(),
                                    "status", "Deleted successfully!")
                    ),
                    HttpStatus.OK
            );
        }
    }

    @DeleteMapping(path = "/user/", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public void deleteUsersWithoutEmail1() throws JsonProcessingException {
        throw new RuntimeException("Delete user without email");
    }

    @DeleteMapping(path = "/user", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public void deleteUsersWithoutEmail2() throws JsonProcessingException {
        throw new RuntimeException("Delete user without email");
    }

    @GetMapping(path = "/user/", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity getUsers() throws JsonProcessingException {
        Deque<Map<String, Object>> body = new ArrayDeque<>();
        Iterable<ApplicationUser> allUsers = userService.findAll();
        allUsers.forEach(user -> {
            body.offer(
                    Map.of("id", user.getId(),
                            "name", user.getName(),
                            "lastname", user.getLastName(),
                            "email", user.getEmail(),
                            "roles", user.getAuthorities()
                                    .stream()
                                    .map(GrantedAuthority::getAuthority)
                                    .sorted())
            );
        });
        return new ResponseEntity(
                objectMapper.writeValueAsString(body),
                HttpStatus.OK
        );

    }

    @PutMapping(path = "/user/role", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity updateUserRole(
            WebRequest request, @AuthenticationPrincipal ApplicationUser userDetails,
            @RequestBody(required = false) RoleManagementRequest roleManagementRequest) throws JsonProcessingException {
        String email = roleManagementRequest.getEmail().toLowerCase();
        String role = roleManagementRequest.getRole();
        ApplicationUserRoleEnum emum;
        boolean isAdmin;
        ApplicationUser user;
        Set<ApplicationUserRole> currentRoles;
        ApplicationUserRole applicationUserRole;
        String operation = roleManagementRequest.getOperation();
        SecurityEventNameEnum securityEventNameEnum;
        String object;

        try {
            emum = ApplicationUserRoleEnum.valueOf(role);
            applicationUserRole = new ApplicationUserRole(emum);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RoleNotFoundException();
        }

        if (!userService.existsByUsername(email)) {
            throw new UserNotFoundException();
        } else {
            user = userService.loadUserByUsername(email);
            isAdmin = user.isAdmin();
            currentRoles = user.getGrantedAuthorities();
        }
        if (!(operation.equals("GRANT") || operation.equals("REMOVE"))) {
            throw new RuntimeException("Operation incorrect.");
        }

        if (isAdmin) {
            if (operation.equals("GRANT")) {
                throw new CombineAdminBusinessRolesException();
            } else {
                throw new RemoveAdministratorException();
            }
        } else {
            if (operation.equals("GRANT") && emum.equals(ApplicationUserRoleEnum.ADMINISTRATOR)) {
                throw new CombineAdminBusinessRolesException();
            } else if (operation.equals("REMOVE")) {
                if (!currentRoles.contains(applicationUserRole)) {
                    throw new UserNotHasRoleException();
                } else if (currentRoles.size() == 1) {
                    throw new RemoveSingleRoleException();
                } else {
                    user.deleteAuthorities(applicationUserRole);
                    securityEventNameEnum = SecurityEventNameEnum.REMOVE_ROLE;
                    object = "Remove role " + role + " from " + email;
                }
            } else {
                user.addAuthorities(applicationUserRole);
                securityEventNameEnum = SecurityEventNameEnum.GRANT_ROLE;
                object = "Grant role " + role + " to " + email;
            }
        }

        userService.save(user);


        String path = request.getDescription(false).replaceAll("uri=", "");
        SecurityEvent securityEvent = new SecurityEvent(LocalDateTime.now(),
                securityEventNameEnum,
                userDetails.getEmail(), object, path);
        securityEventService.save(securityEvent);
        LOGGER.info(securityEvent.toString());

        return new ResponseEntity<>(Map.of("id", user.getId(),
                "name", user.getName(),
                "lastname", user.getLastName(),
                "email", user.getEmail(),
                "roles", currentRoles
                        .stream()
                        .map(GrantedAuthority::getAuthority)
                        .sorted()),
                HttpStatus.OK);
    }

    @PutMapping(path = "/user/access", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_ADMINISTRATOR')")
    public ResponseEntity updateAccountAccess(WebRequest request,
                                              @AuthenticationPrincipal ApplicationUser userDetails,
                                              @RequestBody AccountAccessManagementRequest accountAccessManagementRequest) throws JsonProcessingException {
        String email = accountAccessManagementRequest.getUser().toLowerCase();
        boolean isAdmin;
        ApplicationUser user;
        String operation = accountAccessManagementRequest.getOperation();

        if (!userService.existsByUsername(email)) {
            throw new UserNotFoundException();
        } else {
            user = userService.loadUserByUsername(email);
            isAdmin = user.isAdmin();
        }

        if (!(operation.equals("LOCK") || operation.equals("UNLOCK"))) {
            throw new RuntimeException("Operation incorrect.");
        }

        if (user.isAdmin()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Can't lock the ADMINISTRATOR!");
        }

        String eventMessage;
        String responseMessage;
        SecurityEventNameEnum securityEventNameEnum;
        if (operation.equals("LOCK")) {
            userService.lock(user);
            eventMessage = "Lock user " + email;
            responseMessage = "User " + email + " locked!";
            securityEventNameEnum = SecurityEventNameEnum.LOCK_USER;
        } else {
            userService.unlock(user);
            eventMessage = "Unlock user " + email;
            responseMessage = "User " + email + " unlocked!";
            securityEventNameEnum = SecurityEventNameEnum.UNLOCK_USER;
        }

        SecurityEvent securityEvent = new SecurityEvent(LocalDateTime.now(),
                securityEventNameEnum,
                userDetails.getEmail(), eventMessage, request.getDescription(false).replaceAll("uri=", ""));
        securityEventService.save(securityEvent);
        LOGGER.info(securityEvent.toString());

        return new ResponseEntity<>(Map.of("status", responseMessage),
                HttpStatus.OK);
    }

}
