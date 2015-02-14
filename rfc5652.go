package cms

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

// SignedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithms DigestAlgorithmIdentifiers,
//   encapContentInfo EncapsulatedContentInfo,
//   certificates [0] IMPLICIT CertificateSet OPTIONAL,
//   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
//   signerInfos SignerInfos }

// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier

// SignerInfos ::= SET OF SignerInfo

// EncapsulatedContentInfo ::= SEQUENCE {
//   eContentType ContentType,
//   eContent [0] EXPLICIT OCTET STRING OPTIONAL }

// SignerInfo ::= SEQUENCE {
//   version CMSVersion,
//   sid SignerIdentifier,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
//   signatureAlgorithm SignatureAlgorithmIdentifier,
//   signature SignatureValue,
//   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }

// SignerIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   subjectKeyIdentifier [0] SubjectKeyIdentifier }

// SignedAttributes ::= SET SIZE (1..MAX) OF Attribute

// UnsignedAttributes ::= SET SIZE (1..MAX) OF Attribute

// Attribute ::= SEQUENCE {
//   attrType OBJECT IDENTIFIER,
//   attrValues SET OF AttributeValue }

// AttributeValue ::= ANY

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

// EncryptedContent ::= OCTET STRING
type EncryptedContent []byte

// UnprotectedAttributes ::= SET SIZE (1..MAX) OF Attribute

// RecipientInfo ::= CHOICE {
//   ktri KeyTransRecipientInfo,
//   kari [1] KeyAgreeRecipientInfo,
//   kekri [2] KEKRecipientInfo,
//   pwri [3] PasswordRecipientInfo,
//   ori [4] OtherRecipientInfo }

// EncryptedKey ::= OCTET STRING

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

// RecipientEncryptedKeys ::= SEQUENCE OF RecipientEncryptedKey

// RecipientEncryptedKey ::= SEQUENCE {
//   rid KeyAgreeRecipientIdentifier,
//   encryptedKey EncryptedKey }

// KeyAgreeRecipientIdentifier ::= CHOICE {
//   issuerAndSerialNumber IssuerAndSerialNumber,
//   rKeyId [0] IMPLICIT RecipientKeyIdentifier }

// RecipientKeyIdentifier ::= SEQUENCE {
//   subjectKeyIdentifier SubjectKeyIdentifier,
//   date GeneralizedTime OPTIONAL,
//   other OtherKeyAttribute OPTIONAL }

// SubjectKeyIdentifier ::= OCTET STRING

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

// DigestedData ::= SEQUENCE {
//   version CMSVersion,
//   digestAlgorithm DigestAlgorithmIdentifier,
//   encapContentInfo EncapsulatedContentInfo,
//   digest Digest }

// Digest ::= OCTET STRING

// EncryptedData ::= SEQUENCE {
//   version CMSVersion,
//   encryptedContentInfo EncryptedContentInfo,
//   unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL }

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

// AuthAttributes ::= SET SIZE (1..MAX) OF Attribute

// UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute

// MessageAuthenticationCode ::= OCTET STRING

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

//  IssuerAndSerialNumber ::= SEQUENCE {
//    issuer Name,
//    serialNumber CertificateSerialNumber }

// CMSVersion ::= INTEGER  { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
type CMSVersion int

// UserKeyingMaterial ::= OCTET STRING

// OtherKeyAttribute ::= SEQUENCE {
//   keyAttrId OBJECT IDENTIFIER,
//   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }

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

// UserKeyingMaterial ::= OCTET STRING

// OtherKeyAttribute ::= SEQUENCE {
//   keyAttrId OBJECT IDENTIFIER,
//   keyAttr ANY DEFINED BY keyAttrId OPTIONAL }

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
