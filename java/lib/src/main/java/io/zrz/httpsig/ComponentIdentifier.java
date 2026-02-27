package io.zrz.httpsig;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Identifies a component to include in an HTTP message signature.
 *
 * Each component has a name (e.g. "@method", "content-type") and optional
 * ordered parameters (e.g. ;req, ;sf, ;key="member", ;name="qp").
 */
public record ComponentIdentifier(String name, Map<String, Object> params) {

    public ComponentIdentifier {
        Objects.requireNonNull(name, "name");
        // defensive copy into an ordered map
        params = Map.copyOf(new LinkedHashMap<>(params));
    }

    /** Simple component with no params. */
    public static ComponentIdentifier of(String name) {
        return new ComponentIdentifier(name, Map.of());
    }

    /** @query-param with ;name=<name>. */
    public static ComponentIdentifier queryParam(String name) {
        return new ComponentIdentifier("@query-param", Map.of("name", name));
    }

    /** Wrap any component with the ;req flag for request-bound signatures. */
    public static ComponentIdentifier req(String name) {
        return new ComponentIdentifier(name, Map.of("req", true));
    }

    /** Component with the ;key parameter for extracting a single member from a Dictionary Structured Field header. */
    public static ComponentIdentifier withKey(String name, String key) {
        return new ComponentIdentifier(name, Map.of("key", key));
    }

    /** Component with arbitrary params. */
    public static ComponentIdentifier withParams(String name, Map<String, Object> params) {
        return new ComponentIdentifier(name, new LinkedHashMap<>(params));
    }

    public boolean hasParam(String key) {
        return params.containsKey(key);
    }

    /**
     * Get a param value as a string.
     *
     * @return the string value, or null if absent
     */
    public String paramString(String key) {
        Object v = params.get(key);
        return v instanceof String s ? s : null;
    }
}
