package com.honeytrace.detection;

import java.util.List;
import java.util.regex.Pattern;

/**
 * HT-004: attacker makes a file executable (chmod +x, chmod 777 and similar).
 * Seen right after a script is written with printf or echo, as the step before running it.
 * MITRE ATT&CK T1222.002 File and Directory Permissions Modification: Linux and Mac.
 */
public class ScriptStagingRule extends CommandPatternRule {

    public ScriptStagingRule() {
        super("HT-004", "Script staged and made executable",
                "T1222.002 File and Directory Permissions Modification: Linux and Mac",
                List.of(Pattern.compile("\\bchmod\\s+(\\S*\\+x\\S*|[0-7]{3,4})\\b")));
    }
}