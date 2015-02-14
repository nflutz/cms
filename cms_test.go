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
	{SignatureValue{0x01}, "040101"},
	{SignatureValue{0x01, 0x02}, "04020102"},
	{EncryptedContent{0x01}, "040101"},
	{EncryptedContent{0x01, 0x02}, "04020102"},
	{EncryptedKey{0x01}, "040101"},
	{SubjectKeyIdentifier{0x01}, "040101"},
	{Digest{0x01}, "040101"},
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
