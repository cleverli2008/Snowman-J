package example;

import scheme.IBEET_FTBA;
import utils.Rule;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Minimal FTBA examples using the default time interval rule.
 */
public class DateTime {

    /**
     * Uses the ISO 8601 field order:
     * [year, month, day, hour, minute].
     */
    public static boolean iso8601() {
        IBEET_FTBA scheme = new IBEET_FTBA();
        List<Map<String, Object>> keys = scheme.setup(5, Rule.dateRule());
        Map<String, Object> pk = keys.get(0);
        Map<String, Object> sk = scheme.keyGen(pk, keys.get(1), "1701110680");

        String[] time = {"2024", "2", "29", "23", "30"};
        Map<String, Object> ct = scheme.encrypt(pk, "1701110680", "example".getBytes(StandardCharsets.UTF_8), time);
        Map<String, Object> td = scheme.trapdoor(pk, sk, new String[]{"2024", "*", "29", "23", "30"});
        // System.out.println("pk: " + pk);
        // System.out.println("ct: " + ct);
        // System.out.println("td: " + td);
        return (Boolean) scheme.test(pk, ct, td, ct, td);
    }

    /**
     * Runs the minimal example and prints the final FTBA result.
     */
    public static void main(String[] args) {
        System.out.println("time interval : " + iso8601());
    }
}
