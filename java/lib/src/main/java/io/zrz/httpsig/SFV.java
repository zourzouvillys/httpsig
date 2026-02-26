package io.zrz.httpsig;

import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Structured Field Values (RFC 8941) support, covering only the subset
 * needed for HTTP Message Signatures (RFC 9421).
 *
 * This is not a general-purpose SFV library. It handles dictionaries,
 * inner lists, items, and parameters as required by the signature spec.
 */
public final class SFV {

    private SFV() {}

    // ---- Value types ----

    /** An SFV Token (unquoted identifier). */
    public record Token(String value) {
        public Token { Objects.requireNonNull(value); }
    }

    /** An SFV Item: a bare value plus optional parameters. */
    public record Item(Object value, Params params) {
        public Item { Objects.requireNonNull(params); }
        public Item(Object value) { this(value, Params.EMPTY); }
    }

    /** An SFV Inner List: a list of items plus optional parameters. */
    public record InnerList(List<Item> items, Params params) {
        public InnerList { items = List.copyOf(items); Objects.requireNonNull(params); }
    }

    /** A member of an SFV Dictionary: key -> (item or inner list). */
    public record DictMember(String key, Object value, Params params) {
        public DictMember { Objects.requireNonNull(key); Objects.requireNonNull(params); }
    }

    /** Ordered parameters map. */
    public static final class Params {
        public static final Params EMPTY = new Params(Map.of());

        private final Map<String, Object> map;

        public Params(Map<String, Object> map) {
            this.map = new LinkedHashMap<>(map);
        }

        public Map<String, Object> map() {
            return map;
        }

        public Object get(String key) {
            return map.get(key);
        }

        public boolean has(String key) {
            return map.containsKey(key);
        }

        public boolean isEmpty() {
            return map.isEmpty();
        }
    }

    // ---- Parsing ----

    /**
     * Parse an SFV Dictionary (RFC 8941 Section 3.2).
     * Returns a list of DictMembers preserving order.
     */
    public static List<DictMember> parseDictionary(String input) throws HttpSigException {
        var parser = new Parser(input.trim());
        var result = parser.parseDictionary();
        parser.skipSP();
        if (!parser.eof()) {
            throw new HttpSigException("trailing characters in dictionary at position " + parser.pos);
        }
        return result;
    }

    // ---- Serialization ----

    /**
     * Serialize signature-input parameter list for the (@signature-params) line.
     * Format: (component1 component2 ...);created=...;keyid="..."
     */
    public static String serializeSignatureParams(List<ComponentIdentifier> components, Params params) {
        var sb = new StringBuilder();
        sb.append('(');
        for (int i = 0; i < components.size(); i++) {
            if (i > 0) sb.append(' ');
            sb.append(serializeComponentId(components.get(i)));
        }
        sb.append(')');
        sb.append(serializeParams(params));
        return sb.toString();
    }

    /**
     * Serialize a full SFV Dictionary.
     */
    public static String serializeDictionary(List<DictMember> members) {
        var sb = new StringBuilder();
        for (int i = 0; i < members.size(); i++) {
            if (i > 0) sb.append(", ");
            var m = members.get(i);
            sb.append(m.key());
            sb.append('=');
            if (m.value() instanceof InnerList il) {
                sb.append(serializeInnerList(il));
            } else if (m.value() instanceof Item item) {
                sb.append(serializeBareItem(item.value()));
                sb.append(serializeParams(item.params()));
            } else {
                sb.append(serializeBareItem(m.value()));
            }
            sb.append(serializeParams(m.params()));
        }
        return sb.toString();
    }

    /**
     * Serialize a component identifier (name + params) for the inner list.
     */
    public static String serializeComponentId(ComponentIdentifier cid) {
        var sb = new StringBuilder();
        sb.append(serializeBareItem(cid.name()));
        for (var entry : cid.params().entrySet()) {
            sb.append(';');
            sb.append(entry.getKey());
            Object v = entry.getValue();
            if (v instanceof Boolean b) {
                if (!b) {
                    sb.append("=?0");
                }
                // true is just the key present (boolean true is implicit)
            } else {
                sb.append('=');
                sb.append(serializeBareItem(v));
            }
        }
        return sb.toString();
    }

    /**
     * Serialize bare items per RFC 8941.
     */
    public static String serializeBareItem(Object value) {
        if (value instanceof String s) {
            return serializeString(s);
        } else if (value instanceof byte[] bytes) {
            return ":" + Base64.getEncoder().encodeToString(bytes) + ":";
        } else if (value instanceof Integer i) {
            return i.toString();
        } else if (value instanceof Long l) {
            return l.toString();
        } else if (value instanceof Boolean b) {
            return b ? "?1" : "?0";
        } else if (value instanceof Token t) {
            return t.value();
        } else {
            throw new IllegalArgumentException("unsupported SFV bare item type: " + value.getClass());
        }
    }

    // ---- Internal serialization helpers ----

    private static String serializeString(String s) {
        var sb = new StringBuilder();
        sb.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') {
                sb.append('\\');
            }
            sb.append(c);
        }
        sb.append('"');
        return sb.toString();
    }

    private static String serializeParams(Params params) {
        if (params.isEmpty()) return "";
        var sb = new StringBuilder();
        for (var entry : params.map().entrySet()) {
            sb.append(';');
            sb.append(entry.getKey());
            Object v = entry.getValue();
            if (v instanceof Boolean b) {
                if (!b) {
                    sb.append("=?0");
                }
            } else {
                sb.append('=');
                sb.append(serializeBareItem(v));
            }
        }
        return sb.toString();
    }

    static String serializeInnerList(InnerList il) {
        var sb = new StringBuilder();
        sb.append('(');
        for (int i = 0; i < il.items().size(); i++) {
            if (i > 0) sb.append(' ');
            var item = il.items().get(i);
            sb.append(serializeBareItem(item.value()));
            sb.append(serializeParams(item.params()));
        }
        sb.append(')');
        sb.append(serializeParams(il.params()));
        return sb.toString();
    }

    // ---- Parser ----

    static final class Parser {
        private final String input;
        int pos;

        Parser(String input) {
            this.input = input;
            this.pos = 0;
        }

        boolean eof() {
            return pos >= input.length();
        }

        char peek() {
            return input.charAt(pos);
        }

        char advance() {
            return input.charAt(pos++);
        }

        void expect(char c) throws HttpSigException {
            if (eof() || peek() != c) {
                throw new HttpSigException("expected '" + c + "' at position " + pos);
            }
            pos++;
        }

        void skipSP() {
            while (!eof() && peek() == ' ') pos++;
        }

        void skipOWS() {
            while (!eof() && (peek() == ' ' || peek() == '\t')) pos++;
        }

        // -- Dictionary --

        List<DictMember> parseDictionary() throws HttpSigException {
            var result = new ArrayList<DictMember>();
            if (eof()) return result;
            result.add(parseDictMember());
            while (!eof()) {
                skipOWS();
                if (eof() || peek() != ',') break;
                pos++; // consume ','
                skipOWS();
                if (eof()) {
                    throw new HttpSigException("trailing comma in dictionary");
                }
                result.add(parseDictMember());
            }
            return result;
        }

        private DictMember parseDictMember() throws HttpSigException {
            String key = parseKey();
            Object value;
            Params params;
            if (!eof() && peek() == '=') {
                pos++;
                if (!eof() && peek() == '(') {
                    var il = parseInnerList();
                    value = il;
                    params = Params.EMPTY;
                } else {
                    var item = parseItem();
                    value = item;
                    params = Params.EMPTY;
                }
            } else {
                // bare member, value is boolean true
                params = parseParams();
                value = new Item(true, Params.EMPTY);
            }
            return new DictMember(key, value, params);
        }

        // -- Item --

        Item parseItem() throws HttpSigException {
            Object bare = parseBareItem();
            Params params = parseParams();
            return new Item(bare, params);
        }

        Object parseBareItem() throws HttpSigException {
            if (eof()) throw new HttpSigException("unexpected end of input");
            char c = peek();
            if (c == '"') return parseString();
            if (c == ':') return parseBinary();
            if (c == '?') return parseBoolean();
            if (c == '-' || (c >= '0' && c <= '9')) return parseNumber();
            if (isAlpha(c) || c == '*') return parseToken();
            throw new HttpSigException("unexpected character '" + c + "' at position " + pos);
        }

        // -- String --

        String parseString() throws HttpSigException {
            expect('"');
            var sb = new StringBuilder();
            while (!eof()) {
                char c = advance();
                if (c == '\\') {
                    if (eof()) throw new HttpSigException("unterminated escape in string");
                    char escaped = advance();
                    if (escaped != '"' && escaped != '\\') {
                        throw new HttpSigException("invalid escape \\" + escaped);
                    }
                    sb.append(escaped);
                } else if (c == '"') {
                    return sb.toString();
                } else {
                    sb.append(c);
                }
            }
            throw new HttpSigException("unterminated string");
        }

        // -- Binary --

        byte[] parseBinary() throws HttpSigException {
            expect(':');
            int start = pos;
            while (!eof() && peek() != ':') pos++;
            if (eof()) throw new HttpSigException("unterminated binary sequence");
            String encoded = input.substring(start, pos);
            pos++; // closing ':'
            try {
                return Base64.getDecoder().decode(encoded);
            } catch (IllegalArgumentException e) {
                throw new HttpSigException("invalid base64 in binary", e);
            }
        }

        // -- Boolean --

        Boolean parseBoolean() throws HttpSigException {
            expect('?');
            if (eof()) throw new HttpSigException("unexpected end after '?'");
            char c = advance();
            if (c == '1') return true;
            if (c == '0') return false;
            throw new HttpSigException("invalid boolean value: " + c);
        }

        // -- Number --
        // Returns Integer or Long depending on magnitude. Decimals not supported
        // (we don't need them for signatures).

        Object parseNumber() throws HttpSigException {
            int start = pos;
            if (!eof() && peek() == '-') pos++;
            if (eof() || !isDigit(peek())) {
                throw new HttpSigException("invalid number at position " + start);
            }
            while (!eof() && isDigit(peek())) pos++;
            // check for decimal (not fully supported but let's at least not crash)
            if (!eof() && peek() == '.') {
                pos++;
                while (!eof() && isDigit(peek())) pos++;
            }
            String numStr = input.substring(start, pos);
            try {
                long val = Long.parseLong(numStr);
                if (val >= Integer.MIN_VALUE && val <= Integer.MAX_VALUE) {
                    return (int) val;
                }
                return val;
            } catch (NumberFormatException e) {
                throw new HttpSigException("number out of range: " + numStr);
            }
        }

        // -- Token --

        Token parseToken() throws HttpSigException {
            int start = pos;
            if (eof() || (!isAlpha(peek()) && peek() != '*')) {
                throw new HttpSigException("invalid token start at " + pos);
            }
            pos++;
            while (!eof() && isTokenChar(peek())) pos++;
            return new Token(input.substring(start, pos));
        }

        // -- Parameters --

        Params parseParams() throws HttpSigException {
            var map = new LinkedHashMap<String, Object>();
            while (!eof() && peek() == ';') {
                pos++; // consume ';'
                skipSP();
                String key = parseKey();
                Object value;
                if (!eof() && peek() == '=') {
                    pos++;
                    value = parseBareItem();
                } else {
                    value = true;
                }
                map.put(key, value);
            }
            if (map.isEmpty()) return Params.EMPTY;
            return new Params(map);
        }

        // -- Inner List --

        InnerList parseInnerList() throws HttpSigException {
            expect('(');
            var items = new ArrayList<Item>();
            while (!eof()) {
                skipSP();
                if (peek() == ')') {
                    pos++;
                    Params params = parseParams();
                    return new InnerList(items, params);
                }
                items.add(parseItem());
            }
            throw new HttpSigException("unterminated inner list");
        }

        // -- Key --

        private String parseKey() throws HttpSigException {
            int start = pos;
            if (eof() || (!isLcAlpha(peek()) && peek() != '*')) {
                throw new HttpSigException("invalid key start at " + pos);
            }
            pos++;
            while (!eof() && isKeyChar(peek())) pos++;
            return input.substring(start, pos);
        }

        // -- Character classes --

        private static boolean isAlpha(char c) {
            return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
        }

        private static boolean isLcAlpha(char c) {
            return c >= 'a' && c <= 'z';
        }

        private static boolean isDigit(char c) {
            return c >= '0' && c <= '9';
        }

        private static boolean isTokenChar(char c) {
            return isAlpha(c) || isDigit(c)
                || "!#$%&'*+-.^_`|~:/".indexOf(c) >= 0;
        }

        private static boolean isKeyChar(char c) {
            return isLcAlpha(c) || isDigit(c)
                || c == '_' || c == '-' || c == '.' || c == '*';
        }
    }
}
