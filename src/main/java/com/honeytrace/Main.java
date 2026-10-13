package com.honeytrace;

import com.honeytrace.detection.Alert;
import com.honeytrace.detection.DetectionRule;
import com.honeytrace.detection.RuleSet;
import com.honeytrace.parser.CowrieEvent;
import com.honeytrace.parser.LogParser;
import com.honeytrace.report.Summary;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

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

        List<DetectionRule> rules = RuleSet.defaults();
        List<Alert> alerts = events.stream()
                .flatMap(ev -> rules.stream().map(r -> r.evaluate(ev)))
                .flatMap(Optional::stream)
                .toList();

        System.out.println("Excluded sources: " + excluded);
        System.out.println();
        System.out.print(Summary.render(events, alerts));
    }
}