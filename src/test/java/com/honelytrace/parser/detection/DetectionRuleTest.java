package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectionRulesTest {

    // 203.0.113.0/24 is a documentation range, so these are not real attacker IPs.
    private static CowrieEvent command(String input) {
        return new CowrieEvent("cowrie.command.input", "s1", "203.0.113.7", 4000,
                "2026-10-08T10:36:11.811108Z", null, null, input, null);
    }

    private static CowrieEvent login(String eventId, String user, String pass) {
        return new CowrieEvent(eventId, "s1", "203.0.113.7", 4000,
                "2026-10-08T10:36:11.140040Z", user, pass, null, null);
    }

    private final SystemDiscoveryRule discovery = new SystemDiscoveryRule();
    private final DefaultAccountLoginRule defaults = new DefaultAccountLoginRule();

    @Test
    void flagsUnameFingerprinting() {
        Optional<Alert> alert = discovery.evaluate(command("uname -s -v -n -r -m"));

        assertTrue(alert.isPresent());
        assertEquals("HT-001", alert.get().ruleId());
        assertTrue(alert.get().technique().startsWith("T1082"));
    }

    @Test
    void ignoresBenignCommandsAndNonCommandEvents() {
        assertFalse(discovery.evaluate(command("echo hello")).isPresent());
        assertFalse(discovery.evaluate(login("cowrie.login.success", "root", "x")).isPresent());
    }

    @Test
    void flagsDefaultAccountLogin() {
        Optional<Alert> alert = defaults.evaluate(login("cowrie.login.success", "azureuser", "azureuser"));

        assertTrue(alert.isPresent());
        assertEquals("HT-002", alert.get().ruleId());
        assertEquals("username=azureuser", alert.get().evidence());
    }

    @Test
    void ignoresUnusualUsernames() {
        assertFalse(defaults.evaluate(login("cowrie.login.failed", "k3x9q", "pw")).isPresent());
    }

    @Test
    void alertEvidenceIsSanitized() {
        String nasty = "uname\u0007\u001b[31m\n" + "a".repeat(500);

        Alert alert = discovery.evaluate(command(nasty)).orElseThrow();

        assertTrue(alert.evidence().length() <= 200);
        assertFalse(alert.evidence().chars().anyMatch(Character::isISOControl));
    }
}