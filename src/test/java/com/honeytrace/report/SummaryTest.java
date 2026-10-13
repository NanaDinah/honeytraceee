package com.honeytrace.report;

import com.honeytrace.detection.Alert;
import com.honeytrace.detection.DefaultAccountLoginRule;
import com.honeytrace.detection.DetectionRule;
import com.honeytrace.detection.FileUploadRule;
import com.honeytrace.detection.SystemDiscoveryRule;
import com.honeytrace.parser.CowrieEvent;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SummaryTest {

    // 203.0.113.0/24 is a documentation range, so these are not real attacker IPs.
    private static CowrieEvent event(String type, String ip, String user, String pass,
                                     String input, String file, String sha) {
        return new CowrieEvent(type, "s-" + ip, ip, 4000, "2026-10-13T05:00:00.000000Z",
                user, pass, input, null, file, sha);
    }

    @Test
    void summarisesCountsCredentialsCommandsHashesAndAlerts() {
        List<CowrieEvent> events = List.of(
                event("cowrie.session.connect", "203.0.113.7", null, null, null, null, null),
                event("cowrie.session.connect", "203.0.113.8", null, null, null, null, null),
                event("cowrie.login.success", "203.0.113.7", "root", "123456", null, null, null),
                event("cowrie.login.success", "203.0.113.8", "root", "admin", null, null, null),
                event("cowrie.command.input", "203.0.113.7", null, null, "uname -a", null, null),
                event("cowrie.session.file_upload", "203.0.113.7", null, null, null, "sshd", "deadbeef"));
        List<DetectionRule> rules = List.of(
                new SystemDiscoveryRule(), new DefaultAccountLoginRule(), new FileUploadRule());
        List<Alert> alerts = events.stream()
                .flatMap(e -> rules.stream().map(r -> r.evaluate(e)))
                .flatMap(Optional::stream)
                .toList();

        String out = Summary.render(events, alerts);

        assertTrue(out.contains("Sessions: 2"));
        assertTrue(out.contains("Unique source IPs: 2"));
        assertTrue(out.contains("root"));
        assertTrue(out.contains("123456"));
        assertTrue(out.contains("uname -a"));
        assertTrue(out.contains("deadbeef"));
        assertTrue(out.contains("HT-003"));
    }

    @Test
    void handlesEmptyInput() {
        String out = Summary.render(List.of(), List.of());

        assertTrue(out.contains("Events: 0"));
        assertTrue(out.contains("(none)"));
    }
}