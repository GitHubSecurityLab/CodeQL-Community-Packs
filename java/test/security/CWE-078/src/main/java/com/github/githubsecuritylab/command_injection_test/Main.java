package com.github.githubsecuritylab.command_injection_test;

/* Tests for command injection query
 * 
 * This is suitable for testing static analysis tools, as long as they treat local input as an attack surface (which can be prone to false positives)
 * 
 * (C) Copyright GitHub, 2023
 * 
 */

import java.util.stream.Stream;
import java.io.IOException;
import java.util.Arrays;

public class Main {
    public static void main(String[] args) {
        System.out.println("Command injection test");

        try {
            // 1. array literal
            String[] commandArray1 = new String[]{"/bin/sh", args[2], args[3], args[4]};
            Runtime.getRuntime().exec(commandArray1);

            // 2. array assignment after it is created
            String[] commandArray2 = new String[4];
            commandArray2[0] = "/bin/sh";
            commandArray2[1] = args[2];
            commandArray2[2] = args[3];
            commandArray2[3] = args[4];
            Runtime.getRuntime().exec(commandArray2);

            // 3. Stream concatenation
            Runtime.getRuntime().exec(
                Stream.concat(
                    Arrays.stream(new String[]{"/bin/sh"}),
                    Arrays.stream(new String[]{args[2], args[3], args[4]})
                ).toArray(String[]::new)
            );

        } catch (Exception e) {
            System.err.println("ERROR: " + e.getMessage());
        }

        String script = System.getenv("SCRIPTNAME");

        if (script != null) {
            try {
                // 1. array literal in the args
                Runtime.getRuntime().exec(new String[]{"/bin/sh", script});

                // 2. array literal with dataflow
                String[] commandArray1 = new String[]{"/bin/sh", script};
                Runtime.getRuntime().exec(commandArray1);

                // 3. array assignment after it is created
                String[] commandArray2 = new String[4];
                commandArray2[0] = "/bin/sh";
                commandArray2[1] = script;
                Runtime.getRuntime().exec(commandArray2);

                // 4. Stream concatenation
                Runtime.getRuntime().exec(
                    Stream.concat(
                        Arrays.stream(new String[]{"/bin/sh"}),
                        Arrays.stream(new String[]{script})
                    ).toArray(String[]::new)
                );

            } catch (Exception e) {
                System.err.println("ERROR: " + e.getMessage());
            }
        }
    }
}
