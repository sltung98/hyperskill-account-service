package account.security;

import account.logging.SecurityEvent;
import account.logging.SecurityEventNameEnum;
import account.logging.SecurityEventService;
import account.user.ApplicationUser;
import account.user.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint {
    ObjectMapper objectMapper;
    UserService userService;
    SecurityEventService securityEventService;
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAuthenticationEntryPoint.class);


    public CustomAuthenticationEntryPoint(ObjectMapper objectMapper, UserService userService, SecurityEventService securityEventService) {
        this.objectMapper = objectMapper;
        this.userService = userService;
        this.securityEventService = securityEventService;
    }

    @Override
    public void commence(jakarta.servlet.http.HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        LocalDateTime now = LocalDateTime.now();
        String path = request.getRequestURI();
        String message = "Unauthorized!";
        List<SecurityEventNameEnum> securityEventNameEnumList = new ArrayList<>();
        securityEventNameEnumList.add(SecurityEventNameEnum.LOGIN_FAILED);

        String authHeader = request.getHeader("Authorization");
        if (authHeader != null && authHeader.toLowerCase().startsWith("basic ")) {
            String base64Credentials = authHeader.substring("Basic ".length()).trim();
            String credentials = new String(Base64.getDecoder().decode(base64Credentials));
            String[] parts = credentials.split(":", 2);
            String email = parts[0];
            if (userService.existsByUsername(email)) {
                ApplicationUser user = userService.loadUserByUsername(email);
                if (user.isAdmin()) {
                    message = "Unauthorized!";
                } else {
                    if (user.isAccountNonLocked()) {
                        if (user.getFailedAttempt() <= UserService.MAX_FAILED_ATTEMPTS - 1) {
                            userService.increaseFailedAttempts(user);
                            message = "Unauthorized!";
                        } else {
                            userService.lock(user);
                            securityEventNameEnumList.add(SecurityEventNameEnum.BRUTE_FORCE);
                            securityEventNameEnumList.add(SecurityEventNameEnum.LOCK_USER);
                            message = "User account is locked";
                        }
                    } else {
                        message = "User account is locked";
                        securityEventNameEnumList.clear();
                    }
                }
            }

            securityEventNameEnumList.stream()
                    .forEach(
                            securityEventNameEnum -> {
                                SecurityEvent securityEvent;
                                if(securityEventNameEnum.equals(SecurityEventNameEnum.LOCK_USER)) {
                                    securityEvent = new SecurityEvent(now, securityEventNameEnum,
                                            email, "Lock user " + email, path);
                                } else {
                                    securityEvent = new SecurityEvent(now, securityEventNameEnum,
                                            email, path, path);
                                }
                                securityEventService.save(securityEvent);
                                LOGGER.info(securityEvent.toString());
                            }
                    );
        }

        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(objectMapper.writeValueAsString(
                Map.of("status", HttpStatus.UNAUTHORIZED.value(),
                        "timestamp", now,
                        "error", HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                        "message", message,
                        "path", path))
        );
    }
}