package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CommandPatternRulesTest {

    // 203.0.113.0/24 is a documentation range, so these are not real attacker IPs.
    private static CowrieEvent command(String input) {
        return new CowrieEvent("cowrie.command.input", "s1", "203.0.113.7", 4000,
                "2026-10-13T05:47:57.940980Z", null, null, input, null, null, null);
    }

    private static CowrieEvent login() {
        return new CowrieEvent("cowrie.login.success", "s1", "203.0.113.7", 4000,
                "2026-10-13T05:47:57.940980Z", "root", "x", null, null, null, null);
    }

    private final ScriptStagingRule staging = new ScriptStagingRule();
    private final NetworkDiscoveryRule network = new NetworkDiscoveryRule();

    @Test
    void flagsChmodPlusXAfterWritingScript() {
        String cmd = "printf \"#!/bin/bash\\necho hi\\n\" > filter && chmod +x filter";

        Alert alert = staging.evaluate(command(cmd)).orElseThrow();

        assertEquals("HT-004", alert.ruleId());
        assertTrue(alert.technique().startsWith("T1222.002"));
    }

    @Test
    void flagsNumericChmod() {
        assertTrue(staging.evaluate(command("chmod 777 /tmp/a")).isPresent());
    }

    @Test
    void flagsIfconfigAndIpAddr() {
        assertTrue(network.evaluate(command("ifconfig")).isPresent());
        assertTrue(network.evaluate(command("ip addr show")).isPresent());
        assertEquals("HT-005", network.evaluate(command("ifconfig")).orElseThrow().ruleId());
    }

    @Test
    void flagsRouterOsProbe() {
        assertTrue(network.evaluate(command("/ip cloud print")).isPresent());
    }

    @Test
    void ignoresPlainCommands() {
        assertFalse(staging.evaluate(command("ls -la")).isPresent());
        assertFalse(network.evaluate(command("ls -la")).isPresent());
    }

    @Test
    void ignoresNonCommandEvents() {
        assertFalse(staging.evaluate(login()).isPresent());
        assertFalse(network.evaluate(login()).isPresent());
    }

    @Test
    void doesNotMatchLookalikeWords() {
        assertFalse(network.evaluate(command("echo hip addr")).isPresent());
        assertFalse(staging.evaluate(command("echo chmodel")).isPresent());
    }

    @Test
    void evidenceIsSanitized() {
        Alert alert = staging.evaluate(command("chmod +x a\u0007\n" + "b".repeat(500))).orElseThrow();

        assertTrue(alert.evidence().length() <= 200);
        assertFalse(alert.evidence().chars().anyMatch(Character::isISOControl));
    }

    @Test
    void ruleIdsAreUnique() {
        List<DetectionRule> rules = RuleSet.defaults();

        assertEquals(rules.size(), rules.stream().map(DetectionRule::id).distinct().count());
    }
}