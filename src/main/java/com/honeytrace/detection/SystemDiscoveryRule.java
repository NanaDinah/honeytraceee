package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;

import java.util.List;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * HT-001: attacker runs commands that fingerprint the machine after getting in.
 * Typical of bots checking what they landed on before deciding what to deploy.
 * MITRE ATT&CK T1082 System Information Discovery.
 */
public class SystemDiscoveryRule implements DetectionRule {

    private static final List<Pattern> PATTERNS = List.of(
            Pattern.compile("\\buname\\b"),
            Pattern.compile("\\bwhoami\\b"),
            Pattern.compile("\\bid\\b"),
            Pattern.compile("\\bhostname\\b"),
            Pattern.compile("\\blscpu\\b"),
            Pattern.compile("/proc/(cpuinfo|meminfo|version)"),
            Pattern.compile("/etc/(passwd|os-release|issue)"));

    @Override
    public String id() {
        return "HT-001";
    }

    @Override
    public String name() {
        return "System discovery commands";
    }

    @Override
    public String technique() {
        return "T1082 System Information Discovery";
    }

    @Override
    public Optional<Alert> evaluate(CowrieEvent event) {
        if (!"cowrie.command.input".equals(event.eventId()) || event.input() == null) {
            return Optional.empty();
        }
        boolean hit = PATTERNS.stream().anyMatch(p -> p.matcher(event.input()).find());
        if (!hit) {
            return Optional.empty();
        }
        return Optional.of(new Alert(id(), name(), technique(), event.srcIp(),
                event.session(), event.time(), Alert.clean(event.input())));
    }
}