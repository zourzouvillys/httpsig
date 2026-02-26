package com.zourzouvillys.httpsig;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Extracts component values from HTTP messages per RFC 9421 Section 2.
 *
 * Handles both derived components (@method, @target-uri, etc.) and
 * header fields (plain, ;sf, ;bs, ;key).
 */
final class Components {

    private Components() {}

    /**
     * Extract the value of a component from the message.
     *
     * @param cid    the component to extract
     * @param msg    the HTTP message (request or response)
     * @param reqMsg the related request message (for ;req on responses, or null)
     * @return the extracted string value
     */
    static String extract(ComponentIdentifier cid, HttpMessage msg, HttpMessage reqMsg)
            throws HttpSigException {

        // ;req means extract from the request instead
        if (cid.hasParam("req")) {
            if (reqMsg == null) {
                throw new HttpSigException(";req used but no request message provided");
            }
            // strip the ;req param and extract from the request
            var strippedParams = new java.util.LinkedHashMap<>(cid.params());
            strippedParams.remove("req");
            var strippedCid = ComponentIdentifier.withParams(cid.name(), strippedParams);
            return extract(strippedCid, reqMsg, null);
        }

        String name = cid.name();
        if (name.startsWith("@")) {
            return extractDerived(name, cid, msg);
        }
        return extractHeader(name, cid, msg);
    }

    // ---- Derived components (Section 2.2) ----

    private static String extractDerived(String name, ComponentIdentifier cid, HttpMessage msg)
            throws HttpSigException {
        return switch (name) {
            case "@method" -> {
                requireRequest(msg, name);
                yield msg.method().toUpperCase();
            }
            case "@target-uri" -> {
                requireRequest(msg, name);
                yield msg.url().toASCIIString();
            }
            case "@authority" -> {
                requireRequest(msg, name);
                yield extractAuthority(msg.url());
            }
            case "@scheme" -> {
                requireRequest(msg, name);
                yield msg.url().getScheme().toLowerCase();
            }
            case "@request-target" -> {
                requireRequest(msg, name);
                yield extractRequestTarget(msg.url());
            }
            case "@path" -> {
                requireRequest(msg, name);
                String path = msg.url().getRawPath();
                yield (path == null || path.isEmpty()) ? "/" : path;
            }
            case "@query" -> {
                requireRequest(msg, name);
                String query = msg.url().getRawQuery();
                yield "?" + (query != null ? query : "");
            }
            case "@query-param" -> {
                requireRequest(msg, name);
                String paramName = cid.paramString("name");
                if (paramName == null) {
                    throw new HttpSigException("@query-param requires ;name parameter");
                }
                yield extractQueryParam(msg.url(), paramName);
            }
            case "@status" -> {
                if (msg.isRequest()) {
                    throw new HttpSigException("@status only valid for response messages");
                }
                yield Integer.toString(msg.statusCode());
            }
            default -> throw new HttpSigException("unknown derived component: " + name);
        };
    }

    /**
     * Extract authority from a URI, stripping default ports (80 for http, 443 for https).
     */
    static String extractAuthority(URI uri) {
        String host = uri.getHost().toLowerCase();
        int port = uri.getPort();
        String scheme = uri.getScheme() != null ? uri.getScheme().toLowerCase() : "";
        if (port == -1
            || ("http".equals(scheme) && port == 80)
            || ("https".equals(scheme) && port == 443)) {
            return host;
        }
        return host + ":" + port;
    }

    private static String extractRequestTarget(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) path = "/";
        String query = uri.getRawQuery();
        return query != null ? path + "?" + query : path;
    }

    private static String extractQueryParam(URI uri, String name) throws HttpSigException {
        String query = uri.getRawQuery();
        if (query == null) {
            throw new HttpSigException("@query-param: no query string in URI");
        }
        var values = new ArrayList<String>();
        for (String pair : query.split("&", -1)) {
            String[] kv = pair.split("=", 2);
            String decodedKey = URLDecoder.decode(kv[0], StandardCharsets.UTF_8);
            if (decodedKey.equals(name)) {
                values.add(kv.length > 1
                    ? URLDecoder.decode(kv[1], StandardCharsets.UTF_8)
                    : "");
            }
        }
        if (values.isEmpty()) {
            throw new HttpSigException("@query-param: parameter '" + name + "' not found");
        }
        // RFC 9421 says if multiple values, each one produces a separate entry.
        // For the signature base, we only handle single-value here.
        // Multiple @query-param components with the same ;name should be listed separately.
        return values.get(0);
    }

    // ---- Header fields (Section 2.1) ----

    private static String extractHeader(String name, ComponentIdentifier cid, HttpMessage msg)
            throws HttpSigException {

        List<String> values = msg.headerValues(name);

        if (cid.hasParam("bs")) {
            // Binary Sequence: each value is a separate SFV binary item,
            // combined as an inner list
            return extractByteSequence(name, values);
        }

        if (cid.hasParam("sf")) {
            // Structured Fields: re-serialize as SFV
            return extractStructuredField(name, cid, values);
        }

        if (cid.hasParam("key")) {
            // Dictionary member extraction
            return extractDictKey(name, cid, values);
        }

        // Plain header: concatenate multiple values with ", "
        if (values.isEmpty()) {
            throw new HttpSigException("header '" + name + "' not present in message");
        }
        return values.stream()
            .map(String::trim)
            .collect(Collectors.joining(", "));
    }

    private static String extractByteSequence(String name, List<String> values)
            throws HttpSigException {
        if (values.isEmpty()) {
            throw new HttpSigException("header '" + name + "' not present for ;bs");
        }
        // each value is treated as a binary item, combined in a list
        var parts = new ArrayList<String>();
        for (String v : values) {
            // the value itself is the SFV binary sequence
            parts.add(":" + java.util.Base64.getEncoder().encodeToString(
                v.trim().getBytes(StandardCharsets.UTF_8)) + ":");
        }
        return String.join(", ", parts);
    }

    private static String extractStructuredField(String name, ComponentIdentifier cid,
                                                  List<String> values) throws HttpSigException {
        if (values.isEmpty()) {
            throw new HttpSigException("header '" + name + "' not present for ;sf");
        }
        // just join and return as-is (the field is already in SFV form)
        return values.stream().map(String::trim).collect(Collectors.joining(", "));
    }

    private static String extractDictKey(String name, ComponentIdentifier cid,
                                          List<String> values) throws HttpSigException {
        if (values.isEmpty()) {
            throw new HttpSigException("header '" + name + "' not present for ;key");
        }
        String key = cid.paramString("key");
        if (key == null) {
            throw new HttpSigException(";key parameter requires a string value");
        }
        String combined = values.stream().map(String::trim).collect(Collectors.joining(", "));
        var members = SFV.parseDictionary(combined);
        for (var member : members) {
            if (member.key().equals(key)) {
                // re-serialize the member value
                if (member.value() instanceof SFV.InnerList il) {
                    return serializeInnerListForComponent(il);
                } else if (member.value() instanceof SFV.Item item) {
                    return SFV.serializeBareItem(item.value()) + serializeParams(item.params());
                }
                return SFV.serializeBareItem(member.value());
            }
        }
        throw new HttpSigException(";key member '" + key + "' not found in header '" + name + "'");
    }

    private static String serializeInnerListForComponent(SFV.InnerList il) {
        var sb = new StringBuilder();
        sb.append('(');
        for (int i = 0; i < il.items().size(); i++) {
            if (i > 0) sb.append(' ');
            sb.append(SFV.serializeBareItem(il.items().get(i).value()));
            sb.append(serializeParams(il.items().get(i).params()));
        }
        sb.append(')');
        sb.append(serializeParams(il.params()));
        return sb.toString();
    }

    private static String serializeParams(SFV.Params params) {
        if (params.isEmpty()) return "";
        var sb = new StringBuilder();
        for (var entry : params.map().entrySet()) {
            sb.append(';');
            sb.append(entry.getKey());
            Object v = entry.getValue();
            if (v instanceof Boolean b) {
                if (!b) sb.append("=?0");
            } else {
                sb.append('=');
                sb.append(SFV.serializeBareItem(v));
            }
        }
        return sb.toString();
    }

    private static void requireRequest(HttpMessage msg, String component) throws HttpSigException {
        if (!msg.isRequest()) {
            throw new HttpSigException(component + " only valid for request messages");
        }
    }
}
