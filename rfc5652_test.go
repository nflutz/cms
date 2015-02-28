package cms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"
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
	{RecipientKeyIdentifier{
		SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
		Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
	}, "3012040101170d3135303232303031303230335a"},
	{RecipientKeyIdentifier{
		SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
		Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
		Other: OtherKeyAttribute{
			KeyAttrID: asn1.ObjectIdentifier{1, 2, 3},
		},
	}, "3018040101170d3135303232303031303230335a300406022a03"},
	{SignerInfo{
		Version:              CMSVersion(3),
		SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
		DigestAlgorithmIdentifier: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		Signature: SignatureValue{0x01},
	}, "3015020103800101300406022a03300406022a03040101"},
	{SignerInfo{
		Version: CMSVersion(3),
		IssuerAndSerialNumber: IssuerAndSerialNumber{
			Issuer: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{
						Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
						Value: "www.example.com",
					},
				},
			},
			SerialNumber: big.NewInt(1),
		},
		DigestAlgorithmIdentifier: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		Signature: SignatureValue{0x01},
	}, "3033020103301f301a311830160603550403130f7777772e6578616d706c652e636f6d020101300406022a03300406022a03040101"},
	{SignerInfo{
		Version:              CMSVersion(3),
		SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
		DigestAlgorithmIdentifier: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		SignedAttrs: SignedAttributesSET{
			Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
			Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		Signature: SignatureValue{0x01},
	}, "3033020103800101300406022a03a01c300c06022a033106020101020101300c06022a033106020101020101300406022a03040101"},
	{SignerInfo{
		Version:              CMSVersion(3),
		SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
		DigestAlgorithmIdentifier: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		Signature: SignatureValue{0x01},
		UnsignedAttributes: UnsignedAttributesSET{
			Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
			Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		},
	}, "3033020103800101300406022a03300406022a03040101a11c300c06022a033106020101020101300c06022a033106020101020101"},
	{SignerInfosSET{
		SignerInfo{
			Version:              CMSVersion(3),
			SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
			DigestAlgorithmIdentifier: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 3},
			},
			SignedAttrs: SignedAttributesSET{
				Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
				Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
			},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 3},
			},
			Signature: SignatureValue{0x01},
		},
	}, "31353033020103800101300406022a03a01c300c06022a033106020101020101300c06022a033106020101020101300406022a03040101"},
	{OtherRecipientInfo{
		OriType:  asn1.ObjectIdentifier{1, 2, 3},
		OriValue: int(1),
	}, "300706022a03020101"},
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
	{RecipientEncryptedKey{
		IssuerAndSerialNumber: IssuerAndSerialNumber{
			Issuer: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{
						Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
						Value: "www.example.com",
					},
				},
			},
			SerialNumber: big.NewInt(1),
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "3024301f301a311830160603550403130f7777772e6578616d706c652e636f6d020101040101"},
	{RecipientEncryptedKey{
		RKeyID: RecipientKeyIdentifier{
			SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
			Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "3017a012040101170d3135303232303031303230335a040101"},
	{RecipientEncryptedKeys{
		RecipientEncryptedKey{
			RKeyID: RecipientKeyIdentifier{
				SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
				Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
			},
			EncryptedKey: EncryptedKey{0x01},
		},
	}, "30193017a012040101170d3135303232303031303230335a040101"},
	{KeyAgreeRecipientInfo{
		Version: CMSVersion(3),
		Originator: IssuerAndSerialNumber{
			Issuer: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{
						Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
						Value: "www.example.com",
					},
				},
			},
			SerialNumber: big.NewInt(1),
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		RecipientEncryptedKeys: RecipientEncryptedKeys{
			RecipientEncryptedKey{
				RKeyID: RecipientKeyIdentifier{
					SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
					Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
				},
				EncryptedKey: EncryptedKey{0x01},
			},
		},
	}, "3047020103a021301f301a311830160603550403130f7777772e6578616d706c652e636f6d020101300406022a0330193017a012040101170d3135303232303031303230335a040101"},
	{KeyAgreeRecipientInfo{
		Version:    CMSVersion(3),
		Originator: asn1.RawValue{Tag: 0, Class: 2, IsCompound: false, Bytes: []byte{1}},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		RecipientEncryptedKeys: RecipientEncryptedKeys{
			RecipientEncryptedKey{
				RKeyID: RecipientKeyIdentifier{
					SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
					Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
				},
				EncryptedKey: EncryptedKey{0x01},
			},
		},
	}, "3027020103800101300406022a0330193017a012040101170d3135303232303031303230335a040101"},
	{KeyAgreeRecipientInfo{
		Version: CMSVersion(3),
		Originator: asn1.RawValue{Tag: 1, Class: 2, IsCompound: true, Bytes: []byte{
			0x30, 0x04, 0x06, 0x02, 0x2a, 0x03, 0x03, 0x02, 0x07, 0x80},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		RecipientEncryptedKeys: RecipientEncryptedKeys{
			RecipientEncryptedKey{
				RKeyID: RecipientKeyIdentifier{
					SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
					Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
				},
				EncryptedKey: EncryptedKey{0x01},
			},
		},
	}, "3030020103a10a300406022a0303020780300406022a0330193017a012040101170d3135303232303031303230335a040101"},
	{KeyAgreeRecipientInfo{
		Version:    CMSVersion(3),
		Originator: asn1.RawValue{Tag: 0, Class: 2, IsCompound: false, Bytes: []byte{1}},
		Ukm:        UserKeyingMaterial{0x01},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		RecipientEncryptedKeys: RecipientEncryptedKeys{
			RecipientEncryptedKey{
				RKeyID: RecipientKeyIdentifier{
					SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
					Date:                 time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
				},
				EncryptedKey: EncryptedKey{0x01},
			},
		},
	}, "302c020103800101a103040101300406022a0330193017a012040101170d3135303232303031303230335a040101"},
	{KEKIdentifier{
		KeyIdentifier: []byte{0x01},
	}, "3003040101"},
	{KEKIdentifier{
		KeyIdentifier: []byte{0x01},
		Date:          time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
	}, "3012040101170d3135303232303031303230335a"},
	{KEKIdentifier{
		KeyIdentifier: []byte{0x01},
		Other: OtherKeyAttribute{
			KeyAttrID: asn1.ObjectIdentifier{1, 2, 3},
		},
	}, "3009040101300406022a03"},
	{KEKIdentifier{
		KeyIdentifier: []byte{0x01},
		Date:          time.Date(2015, 2, 20, 01, 02, 03, 0, time.UTC),
		Other: OtherKeyAttribute{
			KeyAttrID: asn1.ObjectIdentifier{1, 2, 3},
		},
	}, "3018040101170d3135303232303031303230335a300406022a03"},
	{KEKRecipientInfo{
		Version: CMSVersion(4),
		Kekid: KEKIdentifier{
			KeyIdentifier: []byte{0x01},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "30110201043003040101300406022a03040101"},
	{DigestedData{
		Version: CMSVersion(1),
		DigestAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncapContentInfo: EncapsulatedContentInfo{
			EContentType: oidContentTypeEncryptedData,
			EContent:     EncryptedContent{0x01},
		},
		Digest: Digest{0x01},
	}, "301e020101300406022a03301006092a864886f70d010706a003040101040101"},
	{PasswordRecipientInfo{
		Version: CMSVersion(0),
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "300c020100300406022a03040101"},
	{PasswordRecipientInfo{
		Version: CMSVersion(0),
		KeyDerivationAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "3012020100a00406022a03300406022a03040101"},
	{KeyTransRecipientInfo{
		Version: CMSVersion(0),
		IssuerAndSerialNumber: IssuerAndSerialNumber{
			Issuer: pkix.RDNSequence{
				pkix.RelativeDistinguishedNameSET{
					pkix.AttributeTypeAndValue{
						Type:  asn1.ObjectIdentifier{2, 5, 4, 3},
						Value: "www.example.com",
					},
				},
			},
			SerialNumber: big.NewInt(1),
		},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "302d020100301f301a311830160603550403130f7777772e6578616d706c652e636f6d020101300406022a03040101"},
	{KeyTransRecipientInfo{
		Version:              CMSVersion(0),
		SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
		KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: asn1.ObjectIdentifier{1, 2, 3},
		},
		EncryptedKey: EncryptedKey{0x01},
	}, "300f020100800101300406022a03040101"},
	{OtherRevocationInfoFormat{
		OtherRevInfoFormat: asn1.ObjectIdentifier{1, 2, 3},
		OtherRevInfo:       asn1.RawValue{Tag: 1, Class: 2, IsCompound: false, Bytes: []byte{1, 2, 3}},
	}, "300906022a038103010203"},
	{OtherCertificateFormat{
		OtherCertFormat: asn1.ObjectIdentifier{1, 2, 3},
		OtherCert:       asn1.RawValue{Tag: 1, Class: 2, IsCompound: false, Bytes: []byte{1, 2, 3}},
	}, "300906022a038103010203"},
	{SignedData{
		Version: CMSVersion(1),
		DigestAlgorithms: DigestAlgorithmIdentifiersSET{
			pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
			pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 3}},
		},
		EncapContentInfo: EncapsulatedContentInfo{oidContentTypeEncryptedData, EncryptedContent{0x01}},
		Certificates: []asn1.RawValue{asn1.RawValue{
			Tag:        3,
			Class:      2,
			IsCompound: true,
			Bytes:      []byte{0x06, 0x02, 0x2a, 0x03, 0x81, 0x03, 0x01, 0x02, 0x03},
		}},
		Crls: []asn1.RawValue{asn1.RawValue{
			Tag:        1,
			Class:      2,
			IsCompound: true,
			Bytes:      []byte{0x06, 0x02, 0x2a, 0x03, 0x81, 0x03, 0x01, 0x02, 0x03},
		}},
		SignerInfos: SignerInfosSET{
			SignerInfo{
				Version:              CMSVersion(3),
				SubjectKeyIdentifier: SubjectKeyIdentifier{0x01},
				DigestAlgorithmIdentifier: pkix.AlgorithmIdentifier{
					Algorithm: asn1.ObjectIdentifier{1, 2, 3},
				},
				SignedAttrs: SignedAttributesSET{
					Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
					Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
				},
				SignatureAlgorithm: pkix.AlgorithmIdentifier{
					Algorithm: asn1.ObjectIdentifier{1, 2, 3},
				},
				Signature: SignatureValue{0x01},
			},
		},
	}, "3074020101310c300406022a03300406022a03301006092a864886f70d010706a003040101a00ba30906022a038103010203a10ba10906022a03810301020331353033020103800101300406022a03a01c300c06022a033106020101020101300c06022a033106020101020101300406022a03040101"},
	{OriginatorInfo{
		Certs: []asn1.RawValue{asn1.RawValue{
			Tag:        3,
			Class:      2,
			IsCompound: true,
			Bytes:      []byte{0x06, 0x02, 0x2a, 0x03, 0x81, 0x03, 0x01, 0x02, 0x03},
		}},
		Crls: []asn1.RawValue{asn1.RawValue{
			Tag:        1,
			Class:      2,
			IsCompound: true,
			Bytes:      []byte{0x06, 0x02, 0x2a, 0x03, 0x81, 0x03, 0x01, 0x02, 0x03},
		}},
	}, "301aa00ba30906022a038103010203a10ba10906022a038103010203"},
	{EnvelopedData{
		Version: CMSVersion(1),
		OriginatorInfo: OriginatorInfo{
			Certs: []asn1.RawValue{asn1.RawValue{
				Tag:        3,
				Class:      2,
				IsCompound: true,
				Bytes:      []byte{0x06, 0x02, 0x2a, 0x03, 0x81, 0x03, 0x01, 0x02, 0x03},
			}},
			Crls: []asn1.RawValue{asn1.RawValue{
				Tag:        1,
				Class:      2,
				IsCompound: true,
				Bytes:      []byte{0x06, 0x02, 0x2a, 0x03, 0x81, 0x03, 0x01, 0x02, 0x03},
			}},
		},
		RecipientInfos: []asn1.RawValue{asn1.RawValue{
			Tag:        1,
			Class:      2,
			IsCompound: true,
			Bytes: []byte{
				0x02, 0x01, 0x03, 0x80, 0x01, 0x01, 0xa1, 0x03, 0x04, 0x01, 0x01, 0x30, 0x04, 0x06,
				0x02, 0x2a, 0x03, 0x30, 0x19, 0x30, 0x17, 0xa0, 0x12, 0x04, 0x01, 0x01, 0x17, 0x0d,
				0x31, 0x35, 0x30, 0x32, 0x32, 0x30, 0x30, 0x31, 0x30, 0x32, 0x30, 0x33, 0x5a, 0x04,
				0x01, 0x01,
			},
		}},
		EncryptedContentInfo: EncryptedContentInfo{
			ContentType: asn1.ObjectIdentifier{1, 2, 3},
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 3},
			},
		},
		UnprotectedAttrs: UnprotectedAttributesSET{
			Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
			Attribute{asn1.ObjectIdentifier{1, 2, 3}, []AttributeValue{int(1), int(1)}},
		},
	}, "3079020101a01aa00ba30906022a038103010203a10ba10906022a038103010203302ea12c020103800101a103040101300406022a0330193017a012040101170d3135303232303031303230335a040101300a06022a03300406022a03a11c300c06022a033106020101020101300c06022a033106020101020101"},
}

func TestMarshalCMS(t *testing.T) {
	for i, test := range marshalCMSTests {
		data, err := asn1.Marshal(test.in)
		if err != nil {
			t.Errorf("#%d failed: %s", i, err)
		}
		out, _ := hex.DecodeString(test.out)
		if !bytes.Equal(out, data) {
			t.Errorf("Test #%d Failed\n     got: %x\nexpected: %x\n", i+1, data, out)
		}
	}
}
