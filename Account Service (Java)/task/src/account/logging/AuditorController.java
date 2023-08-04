package account.logging;

import account.user.UserController;
import account.user.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("api")
public class AuditorController {
    ObjectMapper objectMapper;
    SecurityEventService securityEventService;

    @Autowired
    public AuditorController(ObjectMapper objectMapper, SecurityEventService securityEventService) {
        this.objectMapper = objectMapper;
        this.securityEventService = securityEventService;
    }
    @GetMapping(path = "/security/events/", produces = "application/json")
    @ResponseBody
    @PreAuthorize("hasRole('ROLE_AUDITOR')")
    public ResponseEntity getSecurityEvents() throws JsonProcessingException {
        return new ResponseEntity(
                objectMapper.writeValueAsString(
                        securityEventService.findAll()
                ), HttpStatus.OK
        );
    }
}
