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
	{MessageAuthenticationCode{0x01}, "040101"},
	{UserKeyingMaterial{0x01}, "040101"},
	{MessageDigest{0x01}, "040101"},
	{CMSVersion(1), "020101"},
	{AttCertVersionV1(0), "020100"},
	{oidContentTypeContentInfo, "060B2A864886F70D0109100106"},
	{oidContentTypeData, "06092A864886F70D010701"},
	{oidContentTypeSignedData, "06092A864886F70D010702"},
	{oidContentTypeEnvelopedData, "06092A864886F70D010703"},
	{oidContentTypeDigestData, "06092A864886F70D010705"},
	{oidContentTypeEncryptedData, "06092A864886F70D010706"},
	{oidContentTypeAuthData, "060B2A864886F70D0109100102"},
	{oidAttributeContentType, "06092A864886F70D010903"},
	{oidAttributeMessageDigest, "06092A864886F70D010904"},
	{oidAttributeSigningTime, "06092A864886F70D010905"},
	{oidAttributeCounterSignature, "06092A864886F70D010906"},
	{ContentInfo{oidContentTypeEncryptedData, EncryptedContent{0x01}},
		"301006092A864886F70D010706A003040101"},
	{EncapsulatedContentInfo{oidContentTypeEncryptedData, EncryptedContent{0x01}},
		"301006092A864886F70D010706A003040101"},
	{EncapsulatedContentInfo{oidContentTypeEncryptedData, EncryptedContent{}},
		"300B06092A864886F70D010706"},
	{Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		"300C06022A033106020101020101"},
	{Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{EncryptedKey{0x01}, EncryptedKey{0x01}}},
		"300C06022A033106040101040101"},
	{SignedAttributesSET{
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
	}, "311C300C06022A033106020101020101300C06022A033106020101020101"},
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
