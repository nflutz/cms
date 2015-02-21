package cms

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"
)

// -- Imports from RFC 5280 [PROFILE], Appendix A.1
//       AlgorithmIdentifier, Certificate, CertificateList,
//       CertificateSerialNumber, Name
//          FROM PKIX1Explicit88
//               { iso(1) identified-organization(3) dod(6)
//                 internet(1) security(5) mechanisms(5) pkix(7)
//                 mod(0) pkix1-explicit(18) }

// -- Imports from RFC 3281 [ACPROFILE], Appendix B
//       AttributeCertificate
//          FROM PKIXAttributeCertificate
//               { iso(1) identified-organization(3) dod(6)
//                 internet(1) security(5) mechanisms(5) pkix(7)
//                 mod(0) attribute-cert(12) }

// -- Imports from Appendix B of this document
//       AttributeCertificateV1
//          FROM AttributeCertificateVersion1
//               { iso(1) member-body(2) us(840) rsadsi(113549)
//                 pkcs(1) pkcs-9(9) smime(16) modules(0)
//                 v1AttrCert(15) }

// -- Cryptographic Message Syntax

// ContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   content [0] EXPLICIT ANY DEFINED BY contentType }
// ContentType ::= OBJECT IDENTIFIER
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     interface{} `asn1:"tag:0,explicit"`
}

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//   signerInfos SignerInfos }

// DigestAlgorithmIdentifiersSET ::= SET OF DigestAlgorithmIdentifier
type DigestAlgorithmIdentifiersSET []pkix.AlgorithmIdentifier

// SignerInfos ::= SET OF SignerInfo

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }
type EncapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"tag:0,explicit,optional,omitempty"`
}

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier ::= CHOICE {
//     issuerAndSerialNumber IssuerAndSerialNumber,
//     subjectKeyIdentifier [0] SubjectKeyIdentifier }
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
type SignerInfo struct {
	Version                   CMSVersion
	IssuerAndSerialNumber     IssuerAndSerialNumber `asn1:"optional"`
	SubjectKeyIdentifier      SubjectKeyIdentifier  `asn1:"tag:0,implicit,optional"`
	DigestAlgorithmIdentifier pkix.AlgorithmIdentifier
	SignedAttrs               SignedAttributesSET `asn1:"tag:0,implicit,optional"`
	SignatureAlgorithm        pkix.AlgorithmIdentifier
	Signature                 SignatureValue
	UnsignedAttributes        UnsignedAttributesSET `asn1:"tag:1,implicit,optional"`
}

// SignedAttributesSET ::= SET SIZE (1..MAX) OF Attribute
type SignedAttributesSET []Attribute

// UnsignedAttributesSET ::= SET SIZE (1..MAX) OF Attribute
type UnsignedAttributesSET []Attribute

// Attribute ::= SEQUENCE {
//   attrType OBJECT IDENTIFIER,
//   attrValues SET OF AttributeValue }
type Attribute struct {
	AttrType   asn1.ObjectIdentifier
	AttrValues []AttributeValue `asn1:"set"`
}

// AttributeValue ::= ANY
type AttributeValue interface{}

// SignatureValue ::= OCTET STRING
type SignatureValue []byte

// EnvelopedData ::= SEQUENCE {
//   version CMSVersion,
//   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//   recipientInfos RecipientInfos,
//   encryptedContentInfo EncryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

// OriginatorInfo ::= SEQUENCE {
//   certs [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL }

// RecipientInfos ::= SET SIZE (1..MAX) OF RecipientInfo

// EncryptedContentInfo ::= SEQUENCE {
//   contentType ContentType,
//   contentEncryptionAlgorithm ContentEncryptionAlgorithmIdentifier,
//   encryptedContent [0] IMPLICIT EncryptedContent OPTIONAL }
type EncryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           EncryptedContent `asn1:"implicit,tag:0,optional"`
}

// EncryptedContent ::= OCTET STRING
type EncryptedContent []byte

// UnprotectedAttributesSET ::= SET SIZE (1..MAX) OF Attribute
type UnprotectedAttributesSET []Attribute

// RecipientInfo ::= CHOICE {
//   ktri KeyTransRecipientInfo,
//   kari [1] KeyAgreeRecipientInfo,
//   kekri [2] KEKRecipientInfo,
//   pwri [3] PasswordRecipientInfo,
//   ori [4] OtherRecipientInfo }

// EncryptedKey ::= OCTET STRING
type EncryptedKey []byte

// KeyTransRecipientInfo ::= SEQUENCE {
//   version CMSVersion,  -- always set to 0 or 2
//   rid RecipientIdentifier,
//   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//   encryptedKey EncryptedKey }

// RecipientIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }

// KeyAgreeRecipientInfo ::= SEQUENCE {
//   version CMSVersion,  -- always set to 3
//   originator [0] EXPLICIT OriginatorIdentifierOrKey,
//   ukm [1] EXPLICIT UserKeyingMaterial OPTIONAL,
//   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//   recipientEncryptedKeys RecipientEncryptedKeys }

// OriginatorIdentifierOrKey ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier,
//   originatorKey [1] OriginatorPublicKey }

// OriginatorPublicKey ::= SEQUENCE {
//   algorithm AlgorithmIdentifier,
//   publicKey BIT STRING }
type OriginatorPublicKey struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

// RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey
type RecipientEncryptedKeys []RecipientEncryptedKey

// RecipientEncryptedKey ::= SEQUENCE {
//   rid ::= CHOICE {
//     issuerAndSerialNumber IssuerAndSerialNumber,
//     rKeyId [0] IMPLICIT RecipientKeyIdentifier }
//   encryptedKey EncryptedKey }
type RecipientEncryptedKey struct {
	IssuerAndSerialNumber IssuerAndSerialNumber  `asn1:"optional"`
	RKeyID                RecipientKeyIdentifier `asn1:"implicit,tag:0,optional"`
	EncryptedKey          EncryptedKey
}

// RecipientKeyIdentifier ::= SEQUENCE {
//   subjectKeyIdentifier SubjectKeyIdentifier,
//   date GeneralizedTime OPTIONAL,
//   other OtherKeyAttribute OPTIONAL }
type RecipientKeyIdentifier struct {
	SubjectKeyIdentifier SubjectKeyIdentifier
	Date                 time.Time
	Other                OtherKeyAttribute `asn1:"optional"`
}

// SubjectKeyIdentifier ::= OCTET STRING
type SubjectKeyIdentifier []byte

// KEKRecipientInfo ::= SEQUENCE {
//   version CMSVersion,  -- always set to 4
//   kekid KEKIdentifier,
//   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//   encryptedKey EncryptedKey }

// KEKIdentifier ::= SEQUENCE {
//   keyIdentifier OCTET STRING,
//   date GeneralizedTime OPTIONAL,
//   other OtherKeyAttribute OPTIONAL }

// PasswordRecipientInfo ::= SEQUENCE {
//   version CMSVersion,   -- always set to 0
//   keyDerivationAlgorithm [0] KeyDerivationAlgorithmIdentifier
//                              OPTIONAL,
//   keyEncryptionAlgorithm KeyEncryptionAlgorithmIdentifier,
//   encryptedKey EncryptedKey }

// OtherRecipientInfo ::= SEQUENCE {
//   oriType OBJECT IDENTIFIER,
//   oriValue ANY DEFINED BY oriType }
type OtherRecipientInfo struct {
	OriType  asn1.ObjectIdentifier
	OriValue interface{}
}

// DigestedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   encapContentInfo EncapsulatedContentInfo,
//   digest Digest }

// Digest ::= OCTET STRING
type Digest []byte

// EncryptedData ::= SEQUENCE {
//   version CMSVersion,
//   encryptedContentInfo EncryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }
type EncryptedData struct {
	Version              CMSVersion
	EncryptedContentInfo EncapsulatedContentInfo
	UnprotectedAttrs     UnprotectedAttributesSET `asn1:"implicit,tag:1,optional"`
}

// AuthenticatedData ::= SEQUENCE {
//   version CMSVersion,
//   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
//   recipientInfos RecipientInfos,
//   macAlgorithm MessageAuthenticationCodeAlgorithm,
//   digestAlgorithm [1] DigestAlgorithmIdentifier OPTIONAL,
//   encapContentInfo EncapsulatedContentInfo,
//   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
//   mac MessageAuthenticationCode,
//   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }

// AuthAttributesSET ::= SET SIZE (1..MAX) OF Attribute
type AuthAttributesSET []Attribute

// UnauthAttributesSET ::= SET SIZE (1..MAX) OF Attribute
type UnauthAttributesSET []Attribute

// MessageAuthenticationCode ::= OCTET STRING
type MessageAuthenticationCode []byte

// DigestAlgorithmIdentifier ::= AlgorithmIdentifier

// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier

// KeyEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

// ContentEncryptionAlgorithmIdentifier ::= AlgorithmIdentifier

// MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier

// KeyDerivationAlgorithmIdentifier ::= AlgorithmIdentifier

// RevocationInfoChoices ::= SET OF RevocationInfoChoice

// RevocationInfoChoice ::= CHOICE {
//   crl CertificateList,
//   other [1] IMPLICIT OtherRevocationInfoFormat }

// OtherRevocationInfoFormat ::= SEQUENCE {
//   otherRevInfoFormat OBJECT IDENTIFIER,
//   otherRevInfo ANY DEFINED BY otherRevInfoFormat }

// CertificateChoices ::= CHOICE {
//    certificate Certificate,
//    extendedCertificate [0] IMPLICIT ExtendedCertificate,  -- Obsolete
//    v1AttrCert [1] IMPLICIT AttributeCertificateV1,        -- Obsolete
//    v2AttrCert [2] IMPLICIT AttributeCertificateV2,
//    other [3] IMPLICIT OtherCertificateFormat }

//  AttributeCertificateV2 ::= AttributeCertificate

//  OtherCertificateFormat ::= SEQUENCE {
//    otherCertFormat OBJECT IDENTIFIER,
//    otherCert ANY DEFINED BY otherCertFormat }

//  CertificateSet ::= SET OF CertificateChoices

// IssuerAndSerialNumber ::= SEQUENCE {
//    issuer Name,
//    serialNumber CertificateSerialNumber }
type IssuerAndSerialNumber struct {
	Issuer       pkix.RDNSequence
	SerialNumber *big.Int
}

// CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
type CMSVersion int

// UserKeyingMaterial ::= OCTET STRING
type UserKeyingMaterial []byte

// OtherKeyAttribute ::= SEQUENCE {
//   keyAttrId OBJECT IDENTIFIER,
//   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }
type OtherKeyAttribute struct {
	KeyAttrID asn1.ObjectIdentifier
	KeyAttr   asn1.RawValue `asn1:"optional"`
}

// -- Content Type Object Identifiers
// id-ct-contentInfo OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs9(9) smime(16) ct(1) 6 }
// id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
// id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
// id-envelopedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 3 }
// id-digestedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 5 }
// id-encryptedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs7(7) 6 }
// id-ct-authData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) ct(1) 2 }
var (
	oidContentTypeContentInfo   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 6}
	oidContentTypeData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidContentTypeSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentTypeEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	oidContentTypeDigestData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 5}
	oidContentTypeEncryptedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	oidContentTypeAuthData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 2}
)

// -- The CMS Attributes

// MessageDigest ::= OCTET STRING
type MessageDigest []byte

// SigningTime  ::= Time

// Time ::= CHOICE {
//   utcTime UTCTime,
//   generalTime GeneralizedTime }

// Countersignature ::= SignerInfo

// -- Attribute Object Identifiers
// id-contentType OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 3 }
// id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 4 }
// id-signingTime OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 5 }
// id-countersignature OBJECT IDENTIFIER ::= { iso(1) member-body(2)
//     us(840) rsadsi(113549) pkcs(1) pkcs9(9) 6 }
var (
	oidAttributeContentType      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttributeMessageDigest    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttributeSigningTime      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttributeCounterSignature = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 6}
)

// -- Obsolete Extended Certificate syntax from PKCS #6

// ExtendedCertificateOrCertificate ::= CHOICE {
//   certificate Certificate,
//   extendedCertificate [0] IMPLICIT ExtendedCertificate }

// ExtendedCertificate ::= SEQUENCE {
//   extendedCertificateInfo ExtendedCertificateInfo,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature Signature }

// ExtendedCertificateInfo ::= SEQUENCE {
//   version CMSVersion,
//   certificate Certificate,
//   attributes UnauthAttributes }

// Signature ::= BIT STRING

// AttributeCertificateVersion1
//     { iso(1) member-body(2) us(840) rsadsi(113549)
//       pkcs(1) pkcs-9(9) smime(16) modules(0) v1AttrCert(15) }

// -- Imports from RFC 5280 [PROFILE], Appendix A.1
//       AlgorithmIdentifier, Attribute, CertificateSerialNumber,
//       Extensions, UniqueIdentifier
//          FROM PKIX1Explicit88
//               { iso(1) identified-organization(3) dod(6)
//                 internet(1) security(5) mechanisms(5) pkix(7)
//                 mod(0) pkix1-explicit(18) }

// -- Imports from RFC 5280 [PROFILE], Appendix A.2
//       GeneralNames
//          FROM PKIX1Implicit88
//               { iso(1) identified-organization(3) dod(6)
//                 internet(1) security(5) mechanisms(5) pkix(7)
//                 mod(0) pkix1-implicit(19) }

// -- Imports from RFC 3281 [ACPROFILE], Appendix B
//       AttCertValidityPeriod, IssuerSerial
//          FROM PKIXAttributeCertificate
//               { iso(1) identified-organization(3) dod(6)
//                 internet(1) security(5) mechanisms(5) pkix(7)
//                 mod(0) attribute-cert(12) }

// -- Definition extracted from X.509-1997 [X.509-97], but
// -- different type names are used to avoid collisions.

// AttributeCertificateV1 ::= SEQUENCE {
//   acInfo AttributeCertificateInfoV1,
//   signatureAlgorithm AlgorithmIdentifier,
//   signature BIT STRING }

// AttributeCertificateInfoV1 ::= SEQUENCE {
//   version AttCertVersionV1 DEFAULT v1,
//   subject CHOICE {
//     baseCertificateID [0] IssuerSerial,
//       -- associated with a Public Key Certificate
//     subjectName [1] GeneralNames },
//       -- associated with a name
//   issuer GeneralNames,
//   signature AlgorithmIdentifier,
//   serialNumber CertificateSerialNumber,
//   attCertValidityPeriod AttCertValidityPeriod,
//   attributes SEQUENCE OF Attribute,
//   issuerUniqueID UniqueIdentifier OPTIONAL,
//   extensions Extensions OPTIONAL }

// AttCertVersionV1 ::= INTEGER { v1(0) }
type AttCertVersionV1 int
