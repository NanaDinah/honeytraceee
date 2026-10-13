package com.honeytrace.detection;

import com.honeytrace.parser.CowrieEvent;

import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * HT-002: login attempt using a well-known default or cloud-image account name.
 * Bots spray these usernames hoping a fresh server still has the default account.
 * MITRE ATT&CK T1078.001 Valid Accounts: Default Accounts.
 */
public class DefaultAccountLoginRule implements DetectionRule {

    private static final Set<String> DEFAULT_USERS = Set.of(
            "root", "admin", "administrator", "ubuntu", "ec2-user", "azureuser",
            "pi", "user", "test", "oracle", "postgres", "ftpuser", "debian");

    @Override
    public String id() {
        return "HT-002";
    }

    @Override
    public String name() {
        return "Default account login attempt";
    }

    @Override
    public String technique() {
        return "T1078.001 Valid Accounts: Default Accounts";
    }

    @Override
    public Optional<Alert> evaluate(CowrieEvent event) {
        boolean isLogin = "cowrie.login.success".equals(event.eventId())
                || "cowrie.login.failed".equals(event.eventId());
        if (!isLogin || event.username() == null) {
            return Optional.empty();
        }
        if (!DEFAULT_USERS.contains(event.username().toLowerCase(Locale.ROOT))) {
            return Optional.empty();
        }
        // Evidence records the username only; the password is attacker input and is kept out of alerts.
        return Optional.of(new Alert(id(), name(), technique(), event.srcIp(),
                event.session(), event.time(), Alert.clean("username=" + event.username())));
    }
}