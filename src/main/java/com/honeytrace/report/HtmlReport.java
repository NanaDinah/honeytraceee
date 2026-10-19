package com.honeytrace.report;

import com.honeytrace.detection.Alert;
import com.honeytrace.parser.CowrieEvent;

import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.function.Function;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Renders a self-contained HTML report with inline SVG charts: no scripts, no external files.
 * Everything attackers supplied is HTML-escaped, shortened, and has URLs defanged.
 * Source IP addresses are deliberately not shown, so the report is safe to publish.
 */
public final class HtmlReport {

    private static final Pattern SHA256 = Pattern.compile("[0-9a-f]{64}");
    private static final int MAX_DAYS = 366;

    private HtmlReport() {
    }

    public static String render(List<CowrieEvent> events, List<Alert> alerts, Map<String, String> countryByIp) {
        boolean hasGeo = countryByIp != null && !countryByIp.isEmpty();

        List<CowrieEvent> connects = ofType(events, "cowrie.session.connect");
        long uniqueIps = connects.stream().map(CowrieEvent::srcIp).filter(Objects::nonNull).distinct().count();
        long logins = ofType(events, "cowrie.login.success").size();
        long commands = ofType(events, "cowrie.command.input").size();
        long transfers = events.stream()
                .filter(e -> e.eventId() != null && e.eventId().startsWith("cowrie.session.file_"))
                .count();

        Instant first = events.stream().map(CowrieEvent::time).filter(Objects::nonNull)
                .min(Comparator.naturalOrder()).orElse(null);
        Instant last = events.stream().map(CowrieEvent::time).filter(Objects::nonNull)
                .max(Comparator.naturalOrder()).orElse(null);

        StringBuilder h = new StringBuilder(32_000);
        h.append("<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n")
                .append("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n")
                .append("<title>HoneyTrace findings</title>\n<style>").append(CSS).append("</style>\n</head>\n<body>\n<main>\n");

        h.append("<h1>HoneyTrace findings</h1>\n<p class=\"sub\">SSH honeypot data");
        if (first != null && last != null) {
            h.append(" from ").append(day(first)).append(" to ").append(day(last)).append(" (UTC)");
        }
        h.append(". My own test sessions are excluded.</p>\n");

        h.append("<section class=\"cards\">");
        card(h, "Events", events.size());
        card(h, "Sessions", connects.size());
        card(h, "Unique source IPs", uniqueIps);
        card(h, "Accepted logins", logins);
        card(h, "Commands typed", commands);
        card(h, "File transfers", transfers);
        card(h, "Detection alerts", alerts.size());
        if (hasGeo) {
            card(h, "Countries", countryByIp.values().stream().filter(c -> !c.equals("Unknown")).distinct().count());
        }
        h.append("</section>\n");

        // Sessions per day
        TreeMap<LocalDate, Long> perDay = new TreeMap<>();
        for (CowrieEvent e : connects) {
            Instant t = e.time();
            if (t != null) {
                perDay.merge(t.atZone(ZoneOffset.UTC).toLocalDate(), 1L, Long::sum);
            }
        }
        List<String> dayLabels = new java.util.ArrayList<>();
        List<Long> dayValues = new java.util.ArrayList<>();
        if (!perDay.isEmpty()) {
            LocalDate d = perDay.firstKey();
            int guard = 0;
            while (!d.isAfter(perDay.lastKey()) && guard++ < MAX_DAYS) {
                dayLabels.add(d.toString().substring(5));
                dayValues.add(perDay.getOrDefault(d, 0L));
                d = d.plusDays(1);
            }
        }
        section(h, "Sessions per day", vbars(dayLabels, dayValues, 1));

        // Sessions by hour
        long[] hours = new long[24];
        for (CowrieEvent e : connects) {
            Instant t = e.time();
            if (t != null) {
                hours[t.atZone(ZoneOffset.UTC).getHour()]++;
            }
        }
        List<String> hourLabels = new java.util.ArrayList<>();
        List<Long> hourValues = new java.util.ArrayList<>();
        for (int i = 0; i < 24; i++) {
            hourLabels.add(String.format(Locale.ROOT, "%02d", i));
            hourValues.add(hours[i]);
        }
        section(h, "Sessions by hour of day (UTC)", vbars(hourLabels, hourValues, 3));

        if (hasGeo) {
            section(h, "Sessions by country", hbars(top(connects.stream()
                    .map(e -> countryByIp.getOrDefault(e.srcIp(), "Unknown")), 10)));
        }

        List<CowrieEvent> logs = events.stream()
                .filter(e -> "cowrie.login.success".equals(e.eventId()) || "cowrie.login.failed".equals(e.eventId()))
                .toList();
        section(h, "Top usernames tried", hbars(top(logs.stream().map(CowrieEvent::username), 10)));
        section(h, "Top passwords tried", hbars(top(logs.stream().map(CowrieEvent::password), 10)));
        section(h, "Top commands typed (URLs defanged)", hbars(top(events.stream()
                .filter(e -> "cowrie.command.input".equals(e.eventId()))
                .map(CowrieEvent::input).filter(Objects::nonNull).map(HtmlReport::defang), 10)));

        // Alerts by rule
        h.append("<section>\n<h2>Detection rules</h2>\n");
        Map<String, List<Alert>> byRule = alerts.stream()
                .collect(Collectors.groupingBy(Alert::ruleId, TreeMap::new, Collectors.toList()));
        if (byRule.isEmpty()) {
            h.append("<p class=\"empty\">No alerts.</p>\n");
        } else {
            h.append("<div class=\"scroll\"><table>\n<tr><th>Rule</th><th>What it catches</th><th>MITRE ATT&amp;CK</th>")
                    .append("<th class=\"n\">Alerts</th><th class=\"n\">Source IPs</th></tr>\n");
            byRule.forEach((id, list) -> {
                long ips = list.stream().map(Alert::srcIp).filter(Objects::nonNull).distinct().count();
                Alert a = list.get(0);
                h.append("<tr><td>").append(esc(id)).append("</td><td>").append(esc(a.ruleName()))
                        .append("</td><td><a href=\"").append(esc(mitreUrl(a.technique()))).append("\">")
                        .append(esc(a.technique())).append("</a></td><td class=\"n\">").append(list.size())
                        .append("</td><td class=\"n\">").append(ips).append("</td></tr>\n");
            });
            h.append("</table></div>\n");
        }
        h.append("</section>\n");

        // File hashes
        h.append("<section>\n<h2>Files attackers transferred (identified by hash only)</h2>\n");
        List<Map.Entry<String, Long>> hashes = top(events.stream()
                .filter(e -> e.eventId() != null && e.eventId().startsWith("cowrie.session.file_"))
                .map(CowrieEvent::shasum), 10);
        if (hashes.isEmpty()) {
            h.append("<p class=\"empty\">No file transfers.</p>\n");
        } else {
            h.append("<div class=\"scroll\"><table>\n<tr><th>SHA-256</th><th class=\"n\">Times seen</th></tr>\n");
            for (Map.Entry<String, Long> row : hashes) {
                String hash = row.getKey();
                h.append("<tr><td><code>").append(esc(hash)).append("</code>");
                if (SHA256.matcher(hash).matches()) {
                    h.append(" <a href=\"https://www.virustotal.com/gui/file/").append(hash).append("\">lookup</a>");
                }
                h.append("</td><td class=\"n\">").append(row.getValue()).append("</td></tr>\n");
            }
            h.append("</table></div>\n");
        }
        h.append("</section>\n");

        h.append("<footer>Generated by HoneyTrace. Files are never opened or run; they are identified by hash. ")
                .append("Attacker-supplied text is shown as plain text and URLs are defanged.");
        if (hasGeo) {
            h.append(" <a href=\"https://db-ip.com\">IP Geolocation by DB-IP</a>.");
        }
        h.append("</footer>\n</main>\n</body>\n</html>\n");
        return h.toString();
    }

    // ---------- helpers ----------

    private static List<CowrieEvent> ofType(List<CowrieEvent> events, String type) {
        return events.stream().filter(e -> type.equals(e.eventId())).toList();
    }

    private static String day(Instant t) {
        return t.atZone(ZoneOffset.UTC).toLocalDate().toString();
    }

    private static void card(StringBuilder h, String label, long value) {
        h.append("<div class=\"card\"><div class=\"num\">").append(String.format(Locale.ROOT, "%,d", value))
                .append("</div><div class=\"lab\">").append(esc(label)).append("</div></div>");
    }

    private static void section(StringBuilder h, String title, String body) {
        h.append("<section>\n<h2>").append(esc(title)).append("</h2>\n").append(body).append("\n</section>\n");
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                .replace("\"", "&quot;").replace("'", "&#39;");
    }

    static String defang(String s) {
        return s.replaceAll("(?i)http(s?)://", "hxxp$1://");
    }

    private static String shorten(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max - 1) + "...";
    }

    private static String mitreUrl(String technique) {
        String id = technique == null ? "" : technique.split(" ")[0];
        if (!id.matches("T\\d{4}(\\.\\d{3})?")) {
            return "https://attack.mitre.org/";
        }
        return "https://attack.mitre.org/techniques/" + id.replace('.', '/') + "/";
    }

    private static String f(double v) {
        return String.format(Locale.ROOT, "%.1f", v);
    }

    private static List<Map.Entry<String, Long>> top(Stream<String> values, int limit) {
        return values
                .filter(Objects::nonNull)
                .map(Alert::clean)
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

    private static String hbars(List<Map.Entry<String, Long>> rows) {
        if (rows.isEmpty()) {
            return "<p class=\"empty\">No data.</p>";
        }
        long max = rows.stream().mapToLong(Map.Entry::getValue).max().orElse(1);
        int rowH = 26;
        int width = 640;
        int labelW = 250;
        int barMax = width - labelW - 60;
        int height = rows.size() * rowH + 6;
        StringBuilder sb = new StringBuilder();
        sb.append("<svg viewBox=\"0 0 ").append(width).append(' ').append(height)
                .append("\" class=\"chart\" role=\"img\">");
        int y = 3;
        for (Map.Entry<String, Long> r : rows) {
            int w = (int) Math.max(2, Math.round(barMax * (double) r.getValue() / max));
            sb.append("<g><title>").append(esc(r.getKey())).append(": ").append(r.getValue()).append("</title>")
                    .append("<text class=\"lbl\" fill=\"#1a202c\" x=\"0\" y=\"").append(y + 16).append("\">")
                    .append(esc(shorten(r.getKey(), 30))).append("</text>")
                    .append("<rect class=\"bar\" fill=\"#2b6cb0\" x=\"").append(labelW).append("\" y=\"").append(y + 3)
                    .append("\" width=\"").append(w).append("\" height=\"").append(rowH - 8).append("\" rx=\"3\"/>")
                    .append("<text class=\"val\" fill=\"#5a6578\" x=\"").append(labelW + w + 6).append("\" y=\"").append(y + 16)
                    .append("\">").append(r.getValue()).append("</text></g>");
            y += rowH;
        }
        return sb.append("</svg>").toString();
    }

    private static String vbars(List<String> labels, List<Long> values, int labelEvery) {
        if (values.isEmpty()) {
            return "<p class=\"empty\">No data.</p>";
        }
        int width = 640;
        int height = 220;
        int pad = 10;
        int top = 20;
        int bottom = 28;
        int n = values.size();
        long max = Math.max(1, Collections.max(values));
        double slot = (width - 2.0 * pad) / n;
        double bw = Math.max(2, slot * 0.7);
        StringBuilder sb = new StringBuilder();
        sb.append("<svg viewBox=\"0 0 ").append(width).append(' ').append(height)
                .append("\" class=\"chart\" role=\"img\">");
        for (int i = 0; i < n; i++) {
            double x = pad + i * slot + (slot - bw) / 2;
            double bh = (height - top - bottom) * values.get(i) / (double) max;
            double y = height - bottom - bh;
            sb.append("<g><title>").append(esc(labels.get(i))).append(": ").append(values.get(i)).append("</title>")
                    .append("<rect class=\"bar\" fill=\"#2b6cb0\" x=\"").append(f(x)).append("\" y=\"").append(f(y))
                    .append("\" width=\"").append(f(bw)).append("\" height=\"").append(f(bh)).append("\" rx=\"2\"/>");
            if (values.get(i) > 0 && n <= 31) {
                sb.append("<text class=\"val\" fill=\"#5a6578\" text-anchor=\"middle\" x=\"").append(f(x + bw / 2)).append("\" y=\"")
                        .append(f(y - 4)).append("\">").append(values.get(i)).append("</text>");
            }
            if (i % labelEvery == 0) {
                sb.append("<text class=\"lbl\" fill=\"#1a202c\" text-anchor=\"middle\" x=\"").append(f(x + bw / 2)).append("\" y=\"")
                        .append(height - 10).append("\">").append(esc(labels.get(i))).append("</text>");
            }
            sb.append("</g>");
        }
        return sb.append("</svg>").toString();
    }

    private static final String CSS = """
            :root{--bg:#fff;--card:#f4f6f9;--text:#1a202c;--muted:#5a6578;--accent:#2b6cb0;--border:#d9e0e8}
            @media (prefers-color-scheme:dark){:root{--bg:#0f141a;--card:#18202a;--text:#e6ebf2;--muted:#9aa7b8;--accent:#63a4e8;--border:#2a3644}}
            *{box-sizing:border-box}
            body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
            main{max-width:760px;margin:0 auto;padding:28px 18px 60px}
            h1{font-size:28px;margin:0 0 4px}
            h2{font-size:18px;margin:34px 0 10px}
            .sub{color:var(--muted);margin:0 0 22px}
            .cards{display:flex;flex-wrap:wrap;gap:10px}
            .card{flex:1 1 150px;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:12px 14px}
            .num{font-size:24px;font-weight:700}
            .lab{color:var(--muted);font-size:13px}
            .chart{width:100%;height:auto;display:block}
            .bar{fill:#2b6cb0}
            .lbl{fill:#1a202c;font-size:12px}
            .val{fill:#5a6578;font-size:11px}
            @media (prefers-color-scheme:dark){.bar{fill:#63a4e8}.lbl{fill:#e6ebf2}.val{fill:#9aa7b8}}
            .scroll{overflow-x:auto}
            table{border-collapse:collapse;width:100%;font-size:14px}
            th,td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--border);vertical-align:top}
            th{color:var(--muted);font-weight:600}
            .n{text-align:right}
            code{font-size:12px;word-break:break-all}
            a{color:var(--accent)}
            .empty{color:var(--muted)}
            footer{margin-top:40px;color:var(--muted);font-size:13px;border-top:1px solid var(--border);padding-top:14px}
            """;
}
