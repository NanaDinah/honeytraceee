package com.honeytrace.report;

import com.honeytrace.detection.Alert;
import com.honeytrace.parser.CowrieEvent;

import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Builds a plain-text summary of a honeypot run: volumes, top credentials, top commands,
 * file hashes and alerts grouped by rule. Everything attackers supplied is cleaned and
 * shortened before it is printed.
 */
public final class Summary {

    private static final int MAX_VALUE = 70;

    private Summary() {
    }

    public static String render(List<CowrieEvent> events, List<Alert> alerts) {
        StringBuilder sb = new StringBuilder();

        List<CowrieEvent> connects = events.stream()
                .filter(e -> "cowrie.session.connect".equals(e.eventId()))
                .toList();
        long uniqueIps = connects.stream().map(CowrieEvent::srcIp)
                .filter(Objects::nonNull).distinct().count();
        Instant first = events.stream().map(CowrieEvent::time)
                .filter(Objects::nonNull).min(Comparator.naturalOrder()).orElse(null);
        Instant last = events.stream().map(CowrieEvent::time)
                .filter(Objects::nonNull).max(Comparator.naturalOrder()).orElse(null);

        sb.append("Overview\n");
        sb.append("  Events: ").append(events.size()).append('\n');
        sb.append("  Sessions: ").append(connects.size()).append('\n');
        sb.append("  Unique source IPs: ").append(uniqueIps).append('\n');
        sb.append("  Period: ").append(first == null ? "-" : first)
                .append(" to ").append(last == null ? "-" : last).append('\n');

        section(sb, "Top source IPs (by connections)",
                top(connects.stream().map(CowrieEvent::srcIp), 5));

        List<CowrieEvent> logins = events.stream()
                .filter(e -> "cowrie.login.success".equals(e.eventId())
                        || "cowrie.login.failed".equals(e.eventId()))
                .toList();
        section(sb, "Top usernames tried", top(logins.stream().map(CowrieEvent::username), 10));
        section(sb, "Top passwords tried", top(logins.stream().map(CowrieEvent::password), 10));

        section(sb, "Top commands", top(events.stream()
                .filter(e -> "cowrie.command.input".equals(e.eventId()))
                .map(CowrieEvent::input), 10));

        section(sb, "File transfers by sha256 (files are never opened)", top(events.stream()
                .filter(e -> e.eventId() != null && e.eventId().startsWith("cowrie.session.file_"))
                .map(CowrieEvent::shasum), 10));

        sb.append("\nAlerts by rule (total ").append(alerts.size()).append(")\n");
        Map<String, List<Alert>> byRule = alerts.stream()
                .collect(Collectors.groupingBy(Alert::ruleId, TreeMap::new, Collectors.toList()));
        if (byRule.isEmpty()) {
            sb.append("  (none)\n");
        }
        byRule.forEach((id, list) -> {
            long ips = list.stream().map(Alert::srcIp).filter(Objects::nonNull).distinct().count();
            sb.append(String.format("  %s  %-32s %5d alerts  %4d source IPs  %s%n",
                    id, list.get(0).ruleName(), list.size(), ips, list.get(0).technique()));
        });

        return sb.toString();
    }

    private static List<Map.Entry<String, Long>> top(Stream<String> values, int limit) {
        return values
                .filter(Objects::nonNull)
                .map(Summary::tidy)
                .filter(s -> !s.isBlank())
                .collect(Collectors.groupingBy(Function.identity(), Collectors.counting()))
                .entrySet().stream()
                .sorted((a, b) -> {
                    int byCount = Long.compare(b.getValue(), a.getValue());
                    return byCount != 0 ? byCount : a.getKey().compareTo(b.getKey());
                })
                .limit(limit)
                .toList();
    }

    private static String tidy(String raw) {
        String cleaned = Alert.clean(raw);
        return cleaned.length() <= MAX_VALUE ? cleaned : cleaned.substring(0, MAX_VALUE) + "...";
    }

    private static void section(StringBuilder sb, String title, List<Map.Entry<String, Long>> rows) {
        sb.append('\n').append(title).append('\n');
        if (rows.isEmpty()) {
            sb.append("  (none)\n");
            return;
        }
        rows.forEach(r -> sb.append(String.format("  %6d  %s%n", r.getValue(), r.getKey())));
    }
}