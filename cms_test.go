package cms

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

type marshalCMSTest struct {
	in  interface{}
	out string // Hex string representing DER encoded value
}

var marshalCMSTests = []marshalCMSTest{
	{CMSVersion(1), "020101"},
	{AttCertVersionV1(0), "020100"},
}

func TestMarshalCMS(t *testing.T) {
	for i, test := range marshalCMSTests {
		data, err := asn1.Marshal(test.in)
		if err != nil {
			t.Errorf("#%d failed: %s", i, err)
		}
		out, _ := hex.DecodeString(test.out)
		if !bytes.Equal(out, data) {
			t.Errorf("Test #%d Failed - got: %x expected: %x\n", i+1, data, out)
		}
	}
}
