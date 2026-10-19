package com.honeytrace;

import com.honeytrace.detection.Alert;
import com.honeytrace.detection.DetectionRule;
import com.honeytrace.detection.RuleSet;
import com.honeytrace.enrich.GeoLookup;
import com.honeytrace.parser.CowrieEvent;
import com.honeytrace.parser.LogParser;
import com.honeytrace.report.HtmlReport;
import com.honeytrace.report.Summary;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * Usage: Main &lt;cowrie.json&gt; [ip-to-exclude ...] [--geo=country.csv] [--out=report.html]
 */
public class Main {

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: Main <path-to-cowrie.json> [ip-to-exclude ...] [--geo=country.csv] [--out=report.html]");
            System.exit(1);
        }

        Path file = Path.of(args[0]);
        Set<String> excluded = new HashSet<>();
        Path geoFile = null;
        Path outFile = null;
        for (String arg : Arrays.asList(args).subList(1, args.length)) {
            if (arg.startsWith("--geo=")) {
                geoFile = Path.of(arg.substring("--geo=".length()));
            } else if (arg.startsWith("--out=")) {
                outFile = Path.of(arg.substring("--out=".length()));
            } else {
                excluded.add(arg);
            }
        }

        List<CowrieEvent> events = LogParser.parseFile(file).stream()
                .filter(e -> e.srcIp() == null || !excluded.contains(e.srcIp()))
                .toList();

        List<DetectionRule> rules = RuleSet.defaults();
        List<Alert> alerts = events.stream()
                .flatMap(ev -> rules.stream().map(r -> r.evaluate(ev)))
                .flatMap(Optional::stream)
                .toList();

        Map<String, String> countryByIp = Map.of();
        if (geoFile != null) {
            GeoLookup geo = GeoLookup.fromCsv(geoFile);
            System.out.println("GeoIP ranges loaded: " + geo.size());
            if (geo.size() == 0) {
                System.out.println("WARNING: no IPv4 ranges were read from " + geoFile
                        + ". Check the file format (first line: first_ip,last_ip,...,country_code).");
            }
            countryByIp = events.stream()
                    .filter(e -> "cowrie.session.connect".equals(e.eventId()) && e.srcIp() != null)
                    .map(CowrieEvent::srcIp)
                    .distinct()
                    .collect(Collectors.toMap(Function.identity(),
                            ip -> geo.countryCode(ip).map(GeoLookup::countryName).orElse("Unknown")));
        }

        System.out.println("Excluded sources: " + excluded);
        System.out.println();
        System.out.print(Summary.render(events, alerts));

        if (outFile != null) {
            Path parent = outFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.writeString(outFile, HtmlReport.render(events, alerts, countryByIp));
            System.out.println("\nReport written to " + outFile);
        }
    }
}
