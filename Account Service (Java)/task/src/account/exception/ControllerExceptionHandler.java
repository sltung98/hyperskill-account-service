package account.exception;

import account.logging.SecurityEvent;
import account.logging.SecurityEventNameEnum;
import account.logging.SecurityEventService;
import account.payment.PaymentController;
import account.user.ApplicationUser;
import account.user.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import jakarta.transaction.Transactional;
import jakarta.validation.ConstraintViolationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Objects;

@Transactional
@RestControllerAdvice
@RequestMapping(produces = "application/json")
public class ControllerExceptionHandler {
    ObjectMapper objectMapper;
    SecurityEventService securityEventService;
    UserService userService;

    private static final Logger LOGGER = LoggerFactory.getLogger(ControllerExceptionHandler.class);

    @Autowired
    public ControllerExceptionHandler(ObjectMapper objectMapper, SecurityEventService securityEventService, UserService userService) {
        this.objectMapper = objectMapper;
        this.securityEventService = securityEventService;
        this.userService = userService;
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity handleMethodArgumentNotValidException(
            MethodArgumentNotValidException e, WebRequest request) throws JsonProcessingException {
        String errorMessage = e.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage).filter(Objects::nonNull)
                .reduce(String::concat)
                .orElse(e.getMessage());

        return new ResponseEntity(
                objectMapper.writeValueAsString(
                        Map.of("status", HttpStatus.BAD_REQUEST.value(),
                                "timestamp", LocalDateTime.now(),
                                "error", HttpStatus.BAD_REQUEST.getReasonPhrase(),
                                "message", errorMessage,
                                "path", request.getDescription(false).replaceAll("uri=", ""))
                ), HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity handleConstraintViolationException(
            ConstraintViolationException e, WebRequest request) throws JsonProcessingException {
        return new ResponseEntity(
                objectMapper.writeValueAsString(
                        Map.of("status", HttpStatus.BAD_REQUEST.value(),
                                "timestamp", LocalDateTime.now(),
                                "error", HttpStatus.BAD_REQUEST.getReasonPhrase(),
                                "message", e.getMessage(),
                                "path", request.getDescription(false).replaceAll("uri=", ""))
                ), HttpStatus.BAD_REQUEST
        );
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity handleAccessDeniedException(
            @AuthenticationPrincipal ApplicationUser userDetails,
            AccessDeniedException e, WebRequest request) throws JsonProcessingException {
        LocalDateTime now = LocalDateTime.now();
        String path = request.getDescription(false).replaceAll("uri=", "");
        SecurityEvent securityEvent = new SecurityEvent(now, SecurityEventNameEnum.ACCESS_DENIED,
                userDetails.getEmail(), path, path);
        securityEventService.save(securityEvent);
        LOGGER.info(securityEvent.toString());

        return new ResponseEntity(
                objectMapper.writeValueAsString(
                        Map.of("status", HttpStatus.FORBIDDEN.value(),
                                "timestamp", now,
                                "error", HttpStatus.FORBIDDEN.getReasonPhrase(),
                                "message", "Access Denied!",
                                "path", path)
                ), HttpStatus.FORBIDDEN
        );
    }

}
