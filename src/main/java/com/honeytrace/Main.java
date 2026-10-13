package com.honeytrace;

import com.honeytrace.detection.Alert;
import com.honeytrace.detection.DefaultAccountLoginRule;
import com.honeytrace.detection.DetectionRule;
import com.honeytrace.detection.FileUploadRule;
import com.honeytrace.detection.SystemDiscoveryRule;
import com.honeytrace.parser.CowrieEvent;
import com.honeytrace.parser.LogParser;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

public class Main {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: Main <path-to-cowrie.json> [ip-to-exclude ...]");
            System.exit(1);
        }

        Path file = Path.of(args[0]);
        Set<String> excluded = new HashSet<>(Arrays.asList(args).subList(1, args.length));

        List<CowrieEvent> events = LogParser.parseFile(file).stream()
                .filter(e -> e.srcIp() == null || !excluded.contains(e.srcIp()))
                .toList();

        System.out.println("Excluded sources: " + excluded);
        System.out.println("Events parsed: " + events.size());

        System.out.println("\nEvents by type:");
        Map<String, Long> byType = events.stream()
                .collect(Collectors.groupingBy(CowrieEvent::eventId, TreeMap::new, Collectors.counting()));
        byType.forEach((type, count) -> System.out.printf("  %-28s %d%n", type, count));

        System.out.println("\nTop 5 source IPs (by connections):");
        events.stream()
                .filter(e -> "cowrie.session.connect".equals(e.eventId()) && e.srcIp() != null)
                .collect(Collectors.groupingBy(CowrieEvent::srcIp, Collectors.counting()))
                .entrySet().stream()
                .sorted(Map.Entry.<String, Long>comparingByValue().reversed())
                .limit(5)
                .forEach(e -> System.out.printf("  %-18s %d%n", e.getKey(), e.getValue()));

        List<DetectionRule> rules = List.of(new SystemDiscoveryRule(), new DefaultAccountLoginRule(), new FileUploadRule());
        List<Alert> alerts = events.stream()
                .flatMap(ev -> rules.stream().map(r -> r.evaluate(ev)))
                .flatMap(java.util.Optional::stream)
                .toList();

        System.out.println("\nDetection alerts: " + alerts.size());
        alerts.forEach(a -> System.out.printf("  %s  %s  %-16s %s  [%s]%n",
                a.time(), a.ruleId(), a.srcIp(), a.evidence(), a.technique()));
    }
}