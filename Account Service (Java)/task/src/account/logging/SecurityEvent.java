package account.logging;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;

import java.time.LocalDateTime;
import java.util.Map;

@Data
@Entity
@NoArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    @Column(name = "event_id")
    @JsonIgnore
    private long id;
    private LocalDateTime date;
    private SecurityEventNameEnum action;
    private String subject;
    private String object;
    private String path;

    public SecurityEvent(LocalDateTime date, SecurityEventNameEnum action, String subject, String object, String path) {
        this.date = date;
        this.action = action;
        this.subject = subject;
        this.object = object;
        this.path = path;
    }

    @Override
    public String toString() {
        return Map.of(
                "date", date,
                "action", action.name(),
                "subject", subject,
                "object", object,
                "path", path).toString();
    }
}
