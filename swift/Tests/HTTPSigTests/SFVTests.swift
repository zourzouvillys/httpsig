import Foundation
import Testing
@testable import HTTPSig

@Suite("SFV Parser")
struct SFVTests {

    @Test("Parse simple dictionary")
    func parseSimpleDictionary() throws {
        let members = try SFV.parseDictionary("a=1, b=2")
        #expect(members.count == 2)
        #expect(members[0].key == "a")
        #expect(members[1].key == "b")
        if let item = members[0].item {
            #expect(item.value == .int(1))
        }
    }

    @Test("Parse dictionary with string values")
    func parseDictionaryStrings() throws {
        let members = try SFV.parseDictionary("keyid=\"test-key\", alg=\"rsa-pss-sha512\"")
        #expect(members.count == 2)
        if let item = members[0].item {
            #expect(item.value == .string("test-key"))
        }
    }

    @Test("Parse dictionary with binary value")
    func parseDictionaryBinary() throws {
        let members = try SFV.parseDictionary("sig1=:dGVzdA==:")
        #expect(members.count == 1)
        if let item = members[0].item {
            #expect(item.value == .binary(Data("test".utf8)))
        }
    }

    @Test("Parse dictionary with inner list")
    func parseDictionaryInnerList() throws {
        let members = try SFV.parseDictionary(
            "sig1=(\"@method\" \"@authority\");created=1618884473;keyid=\"test-key\""
        )
        #expect(members.count == 1)
        #expect(members[0].key == "sig1")
        if let il = members[0].innerList {
            #expect(il.items.count == 2)
            #expect(il.items[0].value == .string("@method"))
            #expect(il.items[1].value == .string("@authority"))
            #expect(il.params.getInt("created") == 1618884473)
            #expect(il.params.getString("keyid") == "test-key")
        } else {
            Issue.record("expected inner list")
        }
    }

    @Test("Parse empty inner list with params")
    func parseEmptyInnerListWithParams() throws {
        let members = try SFV.parseDictionary(
            "sig1=();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\""
        )
        #expect(members.count == 1)
        if let il = members[0].innerList {
            #expect(il.items.isEmpty)
            #expect(il.params.getInt("created") == 1618884473)
            #expect(il.params.getString("keyid") == "test-key-rsa-pss")
            #expect(il.params.getString("nonce") == "b3k2pp5k7z-50gnwp.yemd")
        } else {
            Issue.record("expected inner list")
        }
    }

    @Test("Parse bare boolean member")
    func parseBareBooleanMember() throws {
        let members = try SFV.parseDictionary("a, b=?0")
        #expect(members.count == 2)
        if let item = members[0].item {
            #expect(item.value == .bool(true))
        }
        if let item = members[1].item {
            #expect(item.value == .bool(false))
        }
    }

    @Test("Inner list items have string values with params")
    func innerListItemsWithParams() throws {
        // In a dictionary, inner list items can be strings with params.
        let members = try SFV.parseDictionary("sig1=(\"@method\";req \"@path\")")
        #expect(members.count == 1)
        if let il = members[0].innerList {
            #expect(il.items.count == 2)
            #expect(il.items[0].value == .string("@method"))
            #expect(il.items[0].params.has("req"))
            #expect(il.items[1].value == .string("@path"))
        } else {
            Issue.record("expected inner list")
        }
    }

    @Test("Parse token value")
    func parseTokenValue() throws {
        let members = try SFV.parseDictionary("a=token123")
        #expect(members.count == 1)
        if let item = members[0].item {
            #expect(item.value == .token(SFVToken("token123")))
        }
    }

    @Test("Serialize signature params")
    func serializeSignatureParams() throws {
        var params = SFVParams()
        params.set("created", .int(1618884473))
        params.set("keyid", .string("test-key"))

        let components = [
            ComponentIdentifier("@method"),
            ComponentIdentifier("@authority"),
        ]

        let result = SFV.serializeSignatureParams(components, params)
        #expect(result == "(\"@method\" \"@authority\");created=1618884473;keyid=\"test-key\"")
    }

    @Test("Serialize empty component list")
    func serializeEmptyComponentList() throws {
        var params = SFVParams()
        params.set("created", .int(1618884473))
        params.set("keyid", .string("test-key-rsa-pss"))
        params.set("nonce", .string("b3k2pp5k7z-50gnwp.yemd"))

        let result = SFV.serializeSignatureParams([], params)
        #expect(result == "();created=1618884473;keyid=\"test-key-rsa-pss\";nonce=\"b3k2pp5k7z-50gnwp.yemd\"")
    }

    @Test("Serialize component with params")
    func serializeComponentWithParams() throws {
        let cid = ComponentIdentifier.queryParam("name")
        let result = SFV.serializeComponentId(cid)
        #expect(result == "\"@query-param\";name=\"name\"")
    }

    @Test("Serialize component with req flag")
    func serializeComponentReq() throws {
        let cid = ComponentIdentifier.req("@method")
        let result = SFV.serializeComponentId(cid)
        #expect(result == "\"@method\";req")
    }

    @Test("Roundtrip dictionary parse/serialize")
    func roundtripDictionary() throws {
        let input = "sig1=:dGVzdA==:, sig2=:YWJj:"
        let members = try SFV.parseDictionary(input)
        let output = SFV.serializeDictionary(members)
        #expect(output == input)
    }
}
