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
                "2026-10-08T10:36:11.811108Z", null, null, input, null, null, null);
    }

    private static CowrieEvent login(String eventId, String user, String pass) {
        return new CowrieEvent(eventId, "s1", "203.0.113.7", 4000,
                "2026-10-08T10:36:11.140040Z", user, pass, null, null, null, null);
    }

    private static CowrieEvent upload(String eventId, String filename, String sha) {
        return new CowrieEvent(eventId, "s1", "203.0.113.7", 4000,
                "2026-10-13T05:47:57.940980Z", null, null, null, null, filename, sha);
    }

    private final SystemDiscoveryRule discovery = new SystemDiscoveryRule();
    private final DefaultAccountLoginRule defaults = new DefaultAccountLoginRule();
    private final FileUploadRule uploads = new FileUploadRule();

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

    @Test
    void flagsFileUploadWithNameAndHash() {
        Alert alert = uploads.evaluate(upload("cowrie.session.file_upload", "tool.bin", "deadbeef")).orElseThrow();

        assertEquals("HT-003", alert.ruleId());
        assertTrue(alert.technique().startsWith("T1105"));
        assertEquals("file=tool.bin sha256=deadbeef", alert.evidence());
    }

    @Test
    void flagsFileDownloadWithoutFilename() {
        Alert alert = uploads.evaluate(upload("cowrie.session.file_download", null, "deadbeef")).orElseThrow();

        assertEquals("file=- sha256=deadbeef", alert.evidence());
    }

    @Test
    void uploadRuleIgnoresOtherEvents() {
        assertFalse(uploads.evaluate(command("ls")).isPresent());
        assertFalse(uploads.evaluate(login("cowrie.login.success", "root", "x")).isPresent());
    }
}