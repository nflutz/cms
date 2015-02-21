package cms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
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
	{oidContentTypeContentInfo, "060b2a864886f70d0109100106"},
	{oidContentTypeData, "06092a864886f70d010701"},
	{oidContentTypeSignedData, "06092a864886f70d010702"},
	{oidContentTypeEnvelopedData, "06092a864886f70d010703"},
	{oidContentTypeDigestData, "06092a864886f70d010705"},
	{oidContentTypeEncryptedData, "06092a864886f70d010706"},
	{oidContentTypeAuthData, "060b2a864886f70d0109100102"},
	{oidAttributeContentType, "06092a864886f70d010903"},
	{oidAttributeMessageDigest, "06092a864886f70d010904"},
	{oidAttributeSigningTime, "06092a864886f70d010905"},
	{oidAttributeCounterSignature, "06092a864886f70d010906"},
	{ContentInfo{oidContentTypeEncryptedData, EncryptedContent{0x01}},
		"301006092a864886f70d010706a003040101"},
	// TODO: change EncapsulatedContentInfo test to use encapsulatedContent
	{EncapsulatedContentInfo{oidContentTypeEncryptedData, EncryptedContent{0x01}},
		"301006092a864886f70d010706a003040101"},
	{EncapsulatedContentInfo{EContentType: oidContentTypeEncryptedData},
		"300b06092a864886f70d010706"},
	{Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		"300c06022a033106020101020101"},
	{Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{EncryptedKey{0x01}, EncryptedKey{0x01}}},
		"300c06022a033106040101040101"},
	{SignedAttributesSET{}, "3100"},
	{SignedAttributesSET{
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
	}, "311c300c06022a033106020101020101300c06022a033106020101020101"},
	{UnsignedAttributesSET{
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
	}, "311c300c06022a033106020101020101300c06022a033106020101020101"},
	{UnprotectedAttributesSET{
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
	}, "311c300c06022a033106020101020101300c06022a033106020101020101"},
	{AuthAttributesSET{
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
	}, "311c300c06022a033106020101020101300c06022a033106020101020101"},
	{UnauthAttributesSET{
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
	}, "311c300c06022a033106020101020101300c06022a033106020101020101"},
	{DigestAlgorithmIdentifiersSET{
		pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
	}, "310c300406022a03300406022a03"},
	{OtherKeyAttribute{
		KeyAttrID: asn1.ObjectIdentifier{1, 2, 3},
		KeyAttr:   asn1.RawValue{Tag: 1, Class: 2, IsCompound: false, Bytes: []byte{1, 2, 3}},
	}, "300906022a038103010203"},
	{OtherKeyAttribute{KeyAttrID: asn1.ObjectIdentifier{1, 2, 3}}, "300406022a03"},
	{OriginatorPublicKey{
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		PublicKey: asn1.BitString{[]byte{0x80}, 1},
	}, "300a300406022a0303020780"},
	{IssuerAndSerialNumber{
		Issuer: pkix.RDNSequence{
			pkix.RelativeDistinguishedNameSET{
				pkix.AttributeTypeAndValue{
					Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
					Value: "www.example.com",
				},
			},
		},
		SerialNumber: big.NewInt(1),
	}, "301f301a311830160603550403130f7777772e6578616d706c652e636f6d020101"},
	{EncryptedContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 3},
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
	}, "300a06022a03300406022a03"},
	{EncryptedContentInfo{
		ContentType: asn1.ObjectIdentifier{1, 2, 3},
		ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncryptedContent: EncryptedContent{0x01},
	}, "300d06022a03300406022a03800101"},
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
