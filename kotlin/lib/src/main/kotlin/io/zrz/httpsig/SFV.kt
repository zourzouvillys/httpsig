package io.zrz.httpsig

import java.util.Base64

/**
 * Structured Field Values (RFC 8941) support, covering only the subset
 * needed for HTTP Message Signatures (RFC 9421).
 *
 * This is not a general-purpose SFV library. It handles dictionaries,
 * inner lists, items, and parameters as required by the signature spec.
 */
object SFV {

    // ---- Value types ----

    /** An SFV Token (unquoted identifier). */
    data class Token(val value: String)

    /** An SFV Item: a bare value plus optional parameters. */
    data class Item(val value: Any?, val params: Params = Params.EMPTY)

    /** An SFV Inner List: a list of items plus optional parameters. */
    data class InnerList(val items: List<Item>, val params: Params = Params.EMPTY)

    /** A member of an SFV Dictionary: key -> (item or inner list). */
    data class DictMember(val key: String, val value: Any?, val params: Params = Params.EMPTY)

    /** Ordered parameters map. */
    class Params(val map: LinkedHashMap<String, Any?> = linkedMapOf()) {
        companion object {
            val EMPTY = Params()
        }

        constructor(source: Map<String, Any?>) : this(LinkedHashMap(source))

        operator fun get(key: String): Any? = map[key]
        fun has(key: String): Boolean = map.containsKey(key)
        fun isEmpty(): Boolean = map.isEmpty()
    }

    // ---- Parsing ----

    /**
     * Parse an SFV Dictionary (RFC 8941 Section 3.2).
     * Returns a list of DictMembers preserving order.
     */
    fun parseDictionary(input: String): List<DictMember> {
        val parser = Parser(input.trim())
        val result = parser.parseDictionary()
        parser.skipSP()
        if (!parser.eof()) {
            throw HttpSigException("trailing characters in dictionary at position ${parser.pos}")
        }
        return result
    }

    // ---- Serialization ----

    /**
     * Serialize signature-input parameter list for the (@signature-params) line.
     * Format: (component1 component2 ...);created=...;keyid="..."
     */
    fun serializeSignatureParams(components: List<ComponentIdentifier>, params: Params): String =
        buildString {
            append('(')
            components.forEachIndexed { i, cid ->
                if (i > 0) append(' ')
                append(serializeComponentId(cid))
            }
            append(')')
            append(serializeParams(params))
        }

    /**
     * Serialize a full SFV Dictionary.
     */
    fun serializeDictionary(members: List<DictMember>): String =
        buildString {
            members.forEachIndexed { i, m ->
                if (i > 0) append(", ")
                append(m.key)
                append('=')
                when (val v = m.value) {
                    is InnerList -> append(serializeInnerList(v))
                    is Item -> {
                        append(serializeBareItem(v.value))
                        append(serializeParams(v.params))
                    }
                    else -> append(serializeBareItem(v))
                }
                append(serializeParams(m.params))
            }
        }

    /**
     * Serialize a component identifier (name + params) for the inner list.
     */
    fun serializeComponentId(cid: ComponentIdentifier): String =
        buildString {
            append(serializeBareItem(cid.name))
            for ((key, value) in cid.params) {
                append(';')
                append(key)
                if (value is Boolean) {
                    if (!value) append("=?0")
                    // true is just the key present (boolean true is implicit)
                } else {
                    append('=')
                    append(serializeBareItem(value))
                }
            }
        }

    /**
     * Serialize bare items per RFC 8941.
     */
    fun serializeBareItem(value: Any?): String = when (value) {
        is String -> serializeString(value)
        is ByteArray -> ":" + Base64.getEncoder().encodeToString(value) + ":"
        is Int -> value.toString()
        is Long -> value.toString()
        is Boolean -> if (value) "?1" else "?0"
        is Token -> value.value
        else -> throw IllegalArgumentException("unsupported SFV bare item type: ${value?.javaClass}")
    }

    fun serializeInnerList(il: InnerList): String =
        buildString {
            append('(')
            il.items.forEachIndexed { i, item ->
                if (i > 0) append(' ')
                append(serializeBareItem(item.value))
                append(serializeParams(item.params))
            }
            append(')')
            append(serializeParams(il.params))
        }

    // ---- Internal serialization helpers ----

    private fun serializeString(s: String): String =
        buildString {
            append('"')
            for (c in s) {
                if (c == '\\' || c == '"') append('\\')
                append(c)
            }
            append('"')
        }

    private fun serializeParams(params: Params): String {
        if (params.isEmpty()) return ""
        return buildString {
            for ((key, value) in params.map) {
                append(';')
                append(key)
                if (value is Boolean) {
                    if (!value) append("=?0")
                } else {
                    append('=')
                    append(serializeBareItem(value))
                }
            }
        }
    }

    // ---- Parser ----

    internal class Parser(private val input: String) {
        var pos: Int = 0

        fun eof(): Boolean = pos >= input.length
        private fun peek(): Char = input[pos]
        private fun advance(): Char = input[pos++]

        private fun expect(c: Char) {
            if (eof() || peek() != c) {
                throw HttpSigException("expected '$c' at position $pos")
            }
            pos++
        }

        fun skipSP() {
            while (!eof() && peek() == ' ') pos++
        }

        private fun skipOWS() {
            while (!eof() && (peek() == ' ' || peek() == '\t')) pos++
        }

        // -- Dictionary --

        fun parseDictionary(): List<DictMember> {
            val result = mutableListOf<DictMember>()
            if (eof()) return result
            result.add(parseDictMember())
            while (!eof()) {
                skipOWS()
                if (eof() || peek() != ',') break
                pos++ // consume ','
                skipOWS()
                if (eof()) {
                    throw HttpSigException("trailing comma in dictionary")
                }
                result.add(parseDictMember())
            }
            return result
        }

        private fun parseDictMember(): DictMember {
            val key = parseKey()
            return if (!eof() && peek() == '=') {
                pos++
                if (!eof() && peek() == '(') {
                    val il = parseInnerList()
                    DictMember(key, il)
                } else {
                    val item = parseItem()
                    DictMember(key, item)
                }
            } else {
                val params = parseParams()
                DictMember(key, Item(true), params)
            }
        }

        // -- Item --

        fun parseItem(): Item {
            val bare = parseBareItem()
            val params = parseParams()
            return Item(bare, params)
        }

        fun parseBareItem(): Any {
            if (eof()) throw HttpSigException("unexpected end of input")
            return when (val c = peek()) {
                '"' -> parseString()
                ':' -> parseBinary()
                '?' -> parseBoolean()
                '-' -> parseNumber()
                in '0'..'9' -> parseNumber()
                in 'a'..'z', in 'A'..'Z', '*' -> parseToken()
                else -> throw HttpSigException("unexpected character '$c' at position $pos")
            }
        }

        // -- String --

        private fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (!eof()) {
                val c = advance()
                when {
                    c == '\\' -> {
                        if (eof()) throw HttpSigException("unterminated escape in string")
                        val escaped = advance()
                        if (escaped != '"' && escaped != '\\') {
                            throw HttpSigException("invalid escape \\$escaped")
                        }
                        sb.append(escaped)
                    }
                    c == '"' -> return sb.toString()
                    else -> sb.append(c)
                }
            }
            throw HttpSigException("unterminated string")
        }

        // -- Binary --

        private fun parseBinary(): ByteArray {
            expect(':')
            val start = pos
            while (!eof() && peek() != ':') pos++
            if (eof()) throw HttpSigException("unterminated binary sequence")
            val encoded = input.substring(start, pos)
            pos++ // closing ':'
            return try {
                Base64.getDecoder().decode(encoded)
            } catch (e: IllegalArgumentException) {
                throw HttpSigException("invalid base64 in binary", e)
            }
        }

        // -- Boolean --

        private fun parseBoolean(): Boolean {
            expect('?')
            if (eof()) throw HttpSigException("unexpected end after '?'")
            return when (val c = advance()) {
                '1' -> true
                '0' -> false
                else -> throw HttpSigException("invalid boolean value: $c")
            }
        }

        // -- Number --

        private fun parseNumber(): Any {
            val start = pos
            if (!eof() && peek() == '-') pos++
            if (eof() || !peek().isDigit()) {
                throw HttpSigException("invalid number at position $start")
            }
            while (!eof() && peek().isDigit()) pos++
            // check for decimal
            if (!eof() && peek() == '.') {
                pos++
                while (!eof() && peek().isDigit()) pos++
            }
            val numStr = input.substring(start, pos)
            return try {
                val v = numStr.toLong()
                if (v in Int.MIN_VALUE..Int.MAX_VALUE) v.toInt() else v
            } catch (e: NumberFormatException) {
                throw HttpSigException("number out of range: $numStr")
            }
        }

        // -- Token --

        private fun parseToken(): Token {
            val start = pos
            if (eof() || (!peek().isLetter() && peek() != '*')) {
                throw HttpSigException("invalid token start at $pos")
            }
            pos++
            while (!eof() && isTokenChar(peek())) pos++
            return Token(input.substring(start, pos))
        }

        // -- Parameters --

        fun parseParams(): Params {
            val map = linkedMapOf<String, Any?>()
            while (!eof() && peek() == ';') {
                pos++ // consume ';'
                skipSP()
                val key = parseKey()
                val value: Any? = if (!eof() && peek() == '=') {
                    pos++
                    parseBareItem()
                } else {
                    true
                }
                map[key] = value
            }
            return if (map.isEmpty()) Params.EMPTY else Params(map)
        }

        // -- Inner List --

        fun parseInnerList(): InnerList {
            expect('(')
            val items = mutableListOf<Item>()
            while (!eof()) {
                skipSP()
                if (peek() == ')') {
                    pos++
                    val params = parseParams()
                    return InnerList(items, params)
                }
                items.add(parseItem())
            }
            throw HttpSigException("unterminated inner list")
        }

        // -- Key --

        private fun parseKey(): String {
            val start = pos
            if (eof() || (!peek().isLcAlpha() && peek() != '*')) {
                throw HttpSigException("invalid key start at $pos")
            }
            pos++
            while (!eof() && isKeyChar(peek())) pos++
            return input.substring(start, pos)
        }

        // -- Character classes --

        private fun Char.isLcAlpha(): Boolean = this in 'a'..'z'

        private fun isTokenChar(c: Char): Boolean =
            c.isLetter() || c.isDigit() || c in "!#\$%&'*+-.^_`|~:/"

        private fun isKeyChar(c: Char): Boolean =
            c.isLcAlpha() || c.isDigit() || c == '_' || c == '-' || c == '.' || c == '*'

        private fun Char.isDigit(): Boolean = this in '0'..'9'
    }
}
