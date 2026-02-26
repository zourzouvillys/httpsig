package httpsig

import "testing"

func TestSerializeSignatureParams(t *testing.T) {
	tests := []struct {
		name       string
		components []ComponentIdentifier
		params     *SFVParams
		want       string
	}{
		{
			name:       "empty components, no params",
			components: nil,
			params:     nil,
			want:       "()",
		},
		{
			name:       "empty components with created and keyid",
			components: []ComponentIdentifier{},
			params: func() *SFVParams {
				p := NewSFVParams()
				p.Set("created", int64(1618884473))
				p.Set("keyid", "test-key")
				return p
			}(),
			want: `();created=1618884473;keyid="test-key"`,
		},
		{
			name: "multiple components",
			components: []ComponentIdentifier{
				Component("@method"),
				Component("@path"),
				Component("content-type"),
			},
			params: func() *SFVParams {
				p := NewSFVParams()
				p.Set("created", int64(1618884473))
				p.Set("keyid", "my-key")
				return p
			}(),
			want: `("@method" "@path" "content-type");created=1618884473;keyid="my-key"`,
		},
		{
			name: "component with params",
			components: []ComponentIdentifier{
				Component("@authority"),
				QueryParam("Pet"),
			},
			params: func() *SFVParams {
				p := NewSFVParams()
				p.Set("created", int64(1618884473))
				return p
			}(),
			want: `("@authority" "@query-param";name="Pet");created=1618884473`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SerializeSignatureParams(tt.components, tt.params)
			if got != tt.want {
				t.Errorf("got:  %s\nwant: %s", got, tt.want)
			}
		})
	}
}

func TestParseDictionary(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{
			name:    "single binary item",
			input:   `sig1=:dGVzdA==:`,
			wantLen: 1,
		},
		{
			name:    "two items",
			input:   `sig1=:dGVzdA==:, sig2=:YW5vdGhlcg==:`,
			wantLen: 2,
		},
		{
			name:    "inner list",
			input:   `sig1=("@method" "@path");created=1234`,
			wantLen: 1,
		},
		{
			name:    "empty",
			input:   "",
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			members, err := ParseDictionary(tt.input)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if len(members) != tt.wantLen {
				t.Errorf("got %d members, want %d", len(members), tt.wantLen)
			}
		})
	}
}

func TestParseDictionaryInnerList(t *testing.T) {
	input := `sig1=("date" "@method" "@path");created=1618884473;keyid="test-key"`
	members, err := ParseDictionary(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
	m := members[0]
	if m.Key != "sig1" {
		t.Errorf("key = %q, want %q", m.Key, "sig1")
	}
	if m.InnerList == nil {
		t.Fatal("expected inner list")
	}
	if len(m.InnerList.Items) != 3 {
		t.Fatalf("expected 3 items, got %d", len(m.InnerList.Items))
	}
	if m.InnerList.Items[0].Value != "date" {
		t.Errorf("item[0] = %v, want %q", m.InnerList.Items[0].Value, "date")
	}
	if m.InnerList.Params == nil {
		t.Fatal("expected params")
	}
	if created, ok := m.InnerList.Params.Get("created"); !ok || created != int64(1618884473) {
		t.Errorf("created = %v, want 1618884473", created)
	}
	if keyid, ok := m.InnerList.Params.Get("keyid"); !ok || keyid != "test-key" {
		t.Errorf("keyid = %v, want %q", keyid, "test-key")
	}
}

func TestParseDictionaryBinaryValue(t *testing.T) {
	input := `sig1=:dGVzdA==:`
	members, err := ParseDictionary(input)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(members) != 1 {
		t.Fatalf("expected 1 member, got %d", len(members))
	}
	m := members[0]
	if m.Item == nil {
		t.Fatal("expected item")
	}
	bs, ok := m.Item.Value.([]byte)
	if !ok {
		t.Fatalf("expected []byte, got %T", m.Item.Value)
	}
	if string(bs) != "test" {
		t.Errorf("value = %q, want %q", string(bs), "test")
	}
}

func TestSerializeBareItem(t *testing.T) {
	tests := []struct {
		name string
		val  any
		want string
	}{
		{"string", "hello", `"hello"`},
		{"int64", int64(42), "42"},
		{"bool true", true, "?1"},
		{"bool false", false, "?0"},
		{"binary", []byte("test"), ":dGVzdA==:"},
		{"token", Token("rsa-pss-sha512"), "rsa-pss-sha512"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := serializeBareItem(tt.val)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}
