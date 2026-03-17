//! Distinguished Name (DN) builder
//!
//! RFC 5280 compliant X.500 name construction

use const_oid::ObjectIdentifier;
use der::asn1::{Ia5StringRef, PrintableString, Utf8StringRef};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};

use crate::error::{Error, Result};

// Standard attribute OIDs (RFC 5280 Appendix A)
pub mod oid {
    use const_oid::ObjectIdentifier;

    pub const COUNTRY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.6");
    pub const STATE: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.8");
    pub const LOCALITY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.7");
    pub const ORGANIZATION: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");
    pub const ORGANIZATIONAL_UNIT: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.11");
    pub const COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
    pub const SERIAL_NUMBER: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.5");
    pub const EMAIL: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.1");
    // Domain Component (RFC 4519 / LDAP)
    pub const DOMAIN_COMPONENT: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.25");
    // User ID (RFC 4519 / LDAP)
    pub const USER_ID: ObjectIdentifier = ObjectIdentifier::new_unwrap("0.9.2342.19200300.100.1.1");
}

/// Distinguished Name representation
#[derive(Debug, Clone)]
pub struct DistinguishedName {
    /// Domain components (DC) for LDAP-style DNs
    /// e.g., ["com", "rayketcham"] for DC=com,DC=rayketcham
    /// Order: most general (TLD) first, e.g., ["com", "example", "corp"]
    pub domain_components: Vec<String>,
    pub country: Option<String>,
    pub state: Option<String>,
    pub locality: Option<String>,
    pub organization: Option<String>,
    pub organizational_unit: Option<String>,
    pub common_name: String,
    pub serial_number: Option<String>,
    pub email: Option<String>,
    /// User ID (UID) for LDAP-style DNs (OID 0.9.2342.19200300.100.1.1)
    pub uid: Option<String>,
}

impl DistinguishedName {
    /// Create a simple DN with just a common name
    pub fn simple(common_name: impl Into<String>) -> Self {
        Self {
            domain_components: Vec::new(),
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            common_name: common_name.into(),
            serial_number: None,
            email: None,
            uid: None,
        }
    }

    /// Convert to X.509 Name
    pub fn to_name(&self) -> Result<Name> {
        let mut rdns = Vec::new();

        // Order: DC (most general first), then C, ST, L, O, OU, CN (most general to most specific)
        // Domain components: TLD first (e.g., DC=com,DC=rayketcham)
        for dc in &self.domain_components {
            rdns.push(make_rdn(oid::DOMAIN_COMPONENT, dc)?);
        }
        if let Some(ref c) = self.country {
            rdns.push(make_rdn(oid::COUNTRY, c)?);
        }
        if let Some(ref st) = self.state {
            rdns.push(make_rdn(oid::STATE, st)?);
        }
        if let Some(ref l) = self.locality {
            rdns.push(make_rdn(oid::LOCALITY, l)?);
        }
        if let Some(ref o) = self.organization {
            rdns.push(make_rdn(oid::ORGANIZATION, o)?);
        }
        if let Some(ref ou) = self.organizational_unit {
            rdns.push(make_rdn(oid::ORGANIZATIONAL_UNIT, ou)?);
        }
        rdns.push(make_rdn(oid::COMMON_NAME, &self.common_name)?);

        if let Some(ref uid) = self.uid {
            rdns.push(make_rdn(oid::USER_ID, uid)?);
        }
        if let Some(ref sn) = self.serial_number {
            rdns.push(make_rdn(oid::SERIAL_NUMBER, sn)?);
        }
        if let Some(ref email) = self.email {
            rdns.push(make_rdn(oid::EMAIL, email)?);
        }

        Ok(Name::from(RdnSequence::from(rdns)))
    }

    /// Convert to DER-encoded Name
    pub fn to_der(&self) -> Result<Vec<u8>> {
        use der::Encode;
        let name = self.to_name()?;
        name.to_der().map_err(|e| Error::Encoding(e.to_string()))
    }

    /// Parse from RFC 2253 string format
    /// e.g., "CN=Example CA,O=Example Inc,C=US"
    /// Supports DC and UID: "UID=jdoe,DC=com,DC=example,O=CAs,CN=Root CA"
    ///
    /// Note: Multi-valued RDNs (e.g., "CN=foo+UID=bar") are not supported.
    /// The `+` separator within an RDN is not parsed; only `,` separates attributes.
    pub fn from_rfc2253(s: &str) -> Result<Self> {
        let mut dn = Self {
            domain_components: Vec::new(),
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            common_name: String::new(),
            serial_number: None,
            email: None,
            uid: None,
        };

        for part in s.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let value = value.trim();
                match key.trim().to_uppercase().as_str() {
                    "CN" => dn.common_name = value.to_string(),
                    "C" => dn.country = Some(value.to_string()),
                    "ST" | "S" => dn.state = Some(value.to_string()),
                    "L" => dn.locality = Some(value.to_string()),
                    "O" => dn.organization = Some(value.to_string()),
                    "OU" => dn.organizational_unit = Some(value.to_string()),
                    "SERIALNUMBER" => dn.serial_number = Some(value.to_string()),
                    "E" | "EMAIL" | "EMAILADDRESS" => dn.email = Some(value.to_string()),
                    "DC" => dn.domain_components.push(value.to_string()),
                    "UID" | "USERID" => dn.uid = Some(value.to_string()),
                    _ => {} // Ignore unknown attributes
                }
            }
        }

        if dn.common_name.is_empty() {
            return Err(Error::InvalidCertificate("CN is required".into()));
        }

        // Validate all fields (user input boundary)
        dn.validate()?;

        Ok(dn)
    }

    /// Create a DN from a domain name (e.g., "example.com" -> DC=com,DC=example)
    /// Useful for Active Directory style DNs
    pub fn from_domain(domain: &str, common_name: impl Into<String>) -> Self {
        let mut dn = Self::simple(common_name);
        // Split domain and reverse for DC ordering (TLD first)
        dn.domain_components = domain.split('.').rev().map(|s| s.to_string()).collect();
        dn
    }

    /// Convert from an X.509 Name (e.g., from a parsed certificate or CSR subject).
    ///
    /// Extracts all 10 supported attribute types (DC, C, ST, L, O, OU, CN,
    /// UID, SerialNumber, Email). Unknown OIDs are silently ignored.
    ///
    /// Handles PrintableString, UTF8String, and IA5String value encodings.
    pub fn from_x509_name(name: &x509_cert::name::Name) -> Result<Self> {
        use der::{Decode, Encode};

        let mut dn = Self {
            domain_components: Vec::new(),
            country: None,
            state: None,
            locality: None,
            organization: None,
            organizational_unit: None,
            common_name: String::new(),
            serial_number: None,
            email: None,
            uid: None,
        };

        for rdn in name.0.iter() {
            for atav in rdn.0.iter() {
                let oid_str = atav.oid.to_string();
                let value_bytes = atav.value.to_der().map_err(|e| Error::Der(e.to_string()))?;

                // Decode value: try PrintableString, UTF8String, then IA5String
                let value = if let Ok(s) = der::asn1::PrintableStringRef::from_der(&value_bytes) {
                    s.to_string()
                } else if let Ok(s) = der::asn1::Utf8StringRef::from_der(&value_bytes) {
                    s.to_string()
                } else if let Ok(s) = der::asn1::Ia5StringRef::from_der(&value_bytes) {
                    s.to_string()
                } else {
                    continue;
                };

                match oid_str.as_str() {
                    "2.5.4.3" => dn.common_name = value,                // CN
                    "2.5.4.6" => dn.country = Some(value),              // C
                    "2.5.4.8" => dn.state = Some(value),                // ST
                    "2.5.4.7" => dn.locality = Some(value),             // L
                    "2.5.4.10" => dn.organization = Some(value),        // O
                    "2.5.4.11" => dn.organizational_unit = Some(value), // OU
                    "2.5.4.5" => dn.serial_number = Some(value),        // SerialNumber
                    "1.2.840.113549.1.9.1" => dn.email = Some(value),   // Email
                    "0.9.2342.19200300.100.1.25" => dn.domain_components.push(value), // DC
                    "0.9.2342.19200300.100.1.1" => dn.uid = Some(value), // UID
                    _ => {}
                }
            }
        }

        if dn.common_name.is_empty() {
            return Err(Error::InvalidCertificate("No CN in subject".into()));
        }

        Ok(dn)
    }
}

// --- DN field validation ---

/// Max length for CN (RFC 5280 §4.1.2.6 — ub-common-name = 64)
const MAX_CN_LEN: usize = 64;
/// Max length for general DN string fields (RFC 5280 upper bounds)
const MAX_FIELD_LEN: usize = 128;

/// Validate a DN string field: no null bytes, within length limit
fn validate_dn_field(name: &str, value: &str, max_len: usize) -> Result<()> {
    if value.contains('\0') {
        return Err(Error::InvalidCertificate(format!(
            "{} contains null byte",
            name
        )));
    }
    if value.len() > max_len {
        return Err(Error::InvalidCertificate(format!(
            "{} exceeds max length ({} > {})",
            name,
            value.len(),
            max_len
        )));
    }
    if value.trim().is_empty() {
        return Err(Error::InvalidCertificate(format!("{} is empty", name)));
    }
    Ok(())
}

/// Validate country code: exactly 2 ASCII uppercase letters (ISO 3166-1 alpha-2)
fn validate_country(value: &str) -> Result<()> {
    if value.len() != 2 || !value.chars().all(|c| c.is_ascii_uppercase()) {
        return Err(Error::InvalidCertificate(format!(
            "Country must be exactly 2 uppercase ASCII letters (ISO 3166-1), got: {:?}",
            value
        )));
    }
    Ok(())
}

/// Validate email address: basic format check (has @, non-empty local+domain)
fn validate_email(value: &str) -> Result<()> {
    validate_dn_field("Email", value, MAX_FIELD_LEN)?;
    let parts: Vec<&str> = value.splitn(2, '@').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() || !parts[1].contains('.') {
        return Err(Error::InvalidCertificate(format!(
            "Invalid email address format: {:?}",
            value
        )));
    }
    Ok(())
}

impl DistinguishedName {
    /// Validate all DN fields according to RFC 5280 constraints
    pub fn validate(&self) -> Result<()> {
        validate_dn_field("Common Name", &self.common_name, MAX_CN_LEN)?;

        if let Some(ref c) = self.country {
            validate_country(c)?;
        }
        if let Some(ref st) = self.state {
            validate_dn_field("State", st, MAX_FIELD_LEN)?;
        }
        if let Some(ref l) = self.locality {
            validate_dn_field("Locality", l, MAX_FIELD_LEN)?;
        }
        if let Some(ref o) = self.organization {
            validate_dn_field("Organization", o, MAX_FIELD_LEN)?;
        }
        if let Some(ref ou) = self.organizational_unit {
            validate_dn_field("Organizational Unit", ou, MAX_FIELD_LEN)?;
        }
        if let Some(ref sn) = self.serial_number {
            validate_dn_field("Serial Number", sn, MAX_FIELD_LEN)?;
        }
        if let Some(ref email) = self.email {
            validate_email(email)?;
        }
        if let Some(ref uid) = self.uid {
            validate_dn_field("UID", uid, MAX_FIELD_LEN)?;
        }
        for dc in &self.domain_components {
            validate_dn_field("Domain Component", dc, MAX_FIELD_LEN)?;
        }
        Ok(())
    }
}

/// Builder for Distinguished Names
pub struct NameBuilder {
    dn: DistinguishedName,
}

impl NameBuilder {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            dn: DistinguishedName::simple(common_name),
        }
    }

    pub fn country(mut self, c: impl Into<String>) -> Self {
        self.dn.country = Some(c.into());
        self
    }

    pub fn state(mut self, st: impl Into<String>) -> Self {
        self.dn.state = Some(st.into());
        self
    }

    pub fn locality(mut self, l: impl Into<String>) -> Self {
        self.dn.locality = Some(l.into());
        self
    }

    pub fn organization(mut self, o: impl Into<String>) -> Self {
        self.dn.organization = Some(o.into());
        self
    }

    pub fn organizational_unit(mut self, ou: impl Into<String>) -> Self {
        self.dn.organizational_unit = Some(ou.into());
        self
    }

    pub fn serial_number(mut self, sn: impl Into<String>) -> Self {
        self.dn.serial_number = Some(sn.into());
        self
    }

    pub fn email(mut self, email: impl Into<String>) -> Self {
        self.dn.email = Some(email.into());
        self
    }

    pub fn uid(mut self, uid: impl Into<String>) -> Self {
        self.dn.uid = Some(uid.into());
        self
    }

    /// Add a single domain component (e.g., "com", "rayketcham")
    /// Call multiple times for multi-part domains, TLD first
    pub fn domain_component(mut self, dc: impl Into<String>) -> Self {
        self.dn.domain_components.push(dc.into());
        self
    }

    /// Set domain components from a domain name (e.g., "rayketcham.com")
    /// Automatically splits and reverses for correct ordering
    pub fn domain(mut self, domain: &str) -> Self {
        self.dn.domain_components = domain.split('.').rev().map(|s| s.to_string()).collect();
        self
    }

    /// Build the Distinguished Name (no validation — for internal/trusted input)
    pub fn build(self) -> DistinguishedName {
        self.dn
    }

    /// Build and validate the Distinguished Name (for user/external input)
    pub fn build_validated(self) -> Result<DistinguishedName> {
        self.dn.validate()?;
        Ok(self.dn)
    }
}

fn make_rdn(oid: ObjectIdentifier, value: &str) -> Result<RelativeDistinguishedName> {
    use der::asn1::{Any, SetOfVec};
    use der::{Decode, Encode};

    // RFC 4519 §2.4/§2.16: DC and email MUST use IA5String encoding.
    // All other attributes: try PrintableString first, fall back to UTF8String.
    let value_any = if oid == oid::DOMAIN_COMPONENT || oid == oid::EMAIL {
        let ia5 =
            Ia5StringRef::new(value).map_err(|e| Error::Encoding(format!("IA5String: {}", e)))?;
        let der_bytes = ia5.to_der().map_err(|e| Error::Encoding(e.to_string()))?;
        Any::from_der(&der_bytes).map_err(|e| Error::Encoding(e.to_string()))?
    } else if is_printable_string(value) {
        let ps = PrintableString::new(value)
            .map_err(|e| Error::Encoding(format!("PrintableString: {}", e)))?;
        let der_bytes = ps.to_der().map_err(|e| Error::Encoding(e.to_string()))?;
        Any::from_der(&der_bytes).map_err(|e| Error::Encoding(e.to_string()))?
    } else {
        let utf8 =
            Utf8StringRef::new(value).map_err(|e| Error::Encoding(format!("UTF8String: {}", e)))?;
        let der_bytes = utf8.to_der().map_err(|e| Error::Encoding(e.to_string()))?;
        Any::from_der(&der_bytes).map_err(|e| Error::Encoding(e.to_string()))?
    };

    let atav = AttributeTypeAndValue {
        oid,
        value: value_any,
    };

    let set =
        SetOfVec::try_from(vec![atav]).map_err(|e| Error::Encoding(format!("SetOfVec: {}", e)))?;
    Ok(RelativeDistinguishedName::from(set))
}

fn is_printable_string(s: &str) -> bool {
    s.chars().all(|c| {
        c.is_ascii_alphanumeric()
            || c == ' '
            || c == '\''
            || c == '('
            || c == ')'
            || c == '+'
            || c == ','
            || c == '-'
            || c == '.'
            || c == '/'
            || c == ':'
            || c == '='
            || c == '?'
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_dn() {
        let dn = DistinguishedName::simple("Test CA");
        assert_eq!(dn.common_name, "Test CA");
        assert!(dn.country.is_none());
    }

    #[test]
    fn test_name_builder() {
        let dn = NameBuilder::new("Test CA")
            .country("US")
            .organization("Test Inc")
            .build();

        assert_eq!(dn.common_name, "Test CA");
        assert_eq!(dn.country, Some("US".to_string()));
        assert_eq!(dn.organization, Some("Test Inc".to_string()));
    }

    #[test]
    fn test_rfc2253_parse() {
        let dn = DistinguishedName::from_rfc2253("CN=Test CA, O=Example, C=US").unwrap();
        assert_eq!(dn.common_name, "Test CA");
        assert_eq!(dn.organization, Some("Example".to_string()));
        assert_eq!(dn.country, Some("US".to_string()));
    }

    #[test]
    fn test_to_name() {
        let dn = NameBuilder::new("Test")
            .country("US")
            .organization("Org")
            .build();
        let name = dn.to_name().unwrap();
        // Name should be valid X.509 Name
        assert!(!name.0.is_empty());
    }

    #[test]
    fn test_domain_components() {
        let dn = NameBuilder::new("Root CA")
            .domain_component("com")
            .domain_component("rayketcham")
            .organization("CAs")
            .build();
        assert_eq!(dn.domain_components, vec!["com", "rayketcham"]);
        assert_eq!(dn.common_name, "Root CA");
        let name = dn.to_name().unwrap();
        assert!(!name.0.is_empty());
    }

    #[test]
    fn test_domain_from_string() {
        let dn = NameBuilder::new("Root CA")
            .domain("rayketcham.com")
            .organization("CAs")
            .build();
        // Should be reversed: TLD first
        assert_eq!(dn.domain_components, vec!["com", "rayketcham"]);
    }

    #[test]
    fn test_from_domain() {
        let dn = DistinguishedName::from_domain("rayketcham.com", "Root CA");
        assert_eq!(dn.domain_components, vec!["com", "rayketcham"]);
        assert_eq!(dn.common_name, "Root CA");
    }

    #[test]
    fn test_rfc2253_parse_with_dc() {
        let dn = DistinguishedName::from_rfc2253("DC=com,DC=rayketcham,O=CAs,CN=Root CA").unwrap();
        assert_eq!(dn.domain_components, vec!["com", "rayketcham"]);
        assert_eq!(dn.organization, Some("CAs".to_string()));
        assert_eq!(dn.common_name, "Root CA");
    }

    #[test]
    fn test_rfc2253_parse_with_uid() {
        let dn = DistinguishedName::from_rfc2253("UID=jdoe,CN=John Doe,O=Example,C=US").unwrap();
        assert_eq!(dn.uid, Some("jdoe".to_string()));
        assert_eq!(dn.common_name, "John Doe");
        assert_eq!(dn.organization, Some("Example".to_string()));
        assert_eq!(dn.country, Some("US".to_string()));
    }

    #[test]
    fn test_uid_builder() {
        let dn = NameBuilder::new("John Doe")
            .uid("jdoe")
            .organization("Example")
            .build();
        assert_eq!(dn.uid, Some("jdoe".to_string()));
        let name = dn.to_name().unwrap();
        assert!(!name.0.is_empty());
    }

    #[test]
    fn test_uid_roundtrip_via_x509() {
        let original = NameBuilder::new("John Doe")
            .uid("jdoe")
            .organization("Example")
            .country("US")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.uid, Some("jdoe".to_string()));
        assert_eq!(roundtrip.common_name, "John Doe");
        assert_eq!(roundtrip.organization, Some("Example".to_string()));
        assert_eq!(roundtrip.country, Some("US".to_string()));
    }

    // --- Validation tests ---

    #[test]
    fn test_validate_valid_dn() {
        let dn = NameBuilder::new("Test CA")
            .country("US")
            .state("Texas")
            .organization("Example Inc")
            .email("admin@example.com")
            .build();
        assert!(dn.validate().is_ok());
    }

    #[test]
    fn test_validate_cn_too_long() {
        let long_cn = "A".repeat(65);
        let result = NameBuilder::new(long_cn).build_validated();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("exceeds max length"), "got: {}", err);
    }

    #[test]
    fn test_validate_cn_max_length_ok() {
        let max_cn = "A".repeat(64);
        let result = NameBuilder::new(max_cn).build_validated();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_cn_null_byte() {
        let result = NameBuilder::new("Test\0CA").build_validated();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("null byte"), "got: {}", err);
    }

    #[test]
    fn test_validate_cn_empty() {
        let result = NameBuilder::new("   ").build_validated();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("empty"), "got: {}", err);
    }

    #[test]
    fn test_validate_country_invalid_length() {
        let result = NameBuilder::new("Test").country("USA").build_validated();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("ISO 3166-1"), "got: {}", err);
    }

    #[test]
    fn test_validate_country_lowercase() {
        let result = NameBuilder::new("Test").country("us").build_validated();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_country_valid() {
        let result = NameBuilder::new("Test").country("US").build_validated();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_email_no_at() {
        let result = NameBuilder::new("Test")
            .email("not-an-email")
            .build_validated();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("email"), "got: {}", err);
    }

    #[test]
    fn test_validate_email_no_domain_dot() {
        let result = NameBuilder::new("Test")
            .email("user@localhost")
            .build_validated();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_email_valid() {
        let result = NameBuilder::new("Test")
            .email("admin@example.com")
            .build_validated();
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_null_in_org() {
        let result = NameBuilder::new("Test")
            .organization("Bad\0Org")
            .build_validated();
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_field_too_long() {
        let long = "X".repeat(129);
        let result = NameBuilder::new("Test")
            .organization(&long)
            .build_validated();
        assert!(result.is_err());
    }

    #[test]
    fn test_rfc2253_rejects_invalid_country() {
        let result = DistinguishedName::from_rfc2253("CN=Test,C=USA");
        assert!(result.is_err());
    }

    #[test]
    fn test_rfc2253_rejects_null_byte() {
        let result = DistinguishedName::from_rfc2253("CN=Test\0Bad,C=US");
        assert!(result.is_err());
    }

    // --- Special character tests ---

    #[test]
    fn test_dn_cn_with_comma_via_builder() {
        // Commas in CN are valid in X.500 — builder should handle them
        let dn = NameBuilder::new("Doe, John").organization("Acme").build();
        assert_eq!(dn.common_name, "Doe, John");
        // Should encode to X.509 Name successfully (comma is PrintableString-legal)
        let name = dn.to_name().unwrap();
        assert!(!name.0.is_empty());
    }

    #[test]
    fn test_dn_cn_with_comma_roundtrip_via_x509() {
        // Build DN with comma in CN, encode to X.509, then parse back
        let original = NameBuilder::new("Doe, John")
            .organization("Acme Corp")
            .country("US")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.common_name, "Doe, John");
        assert_eq!(roundtrip.organization, Some("Acme Corp".to_string()));
    }

    #[test]
    fn test_rfc2253_comma_in_cn_not_escaped() {
        // from_rfc2253 splits on commas naively — a bare comma in CN
        // causes a mis-parse. This test documents current behavior.
        let result = DistinguishedName::from_rfc2253("CN=Doe, John,O=Acme,C=US");
        // The parser splits "CN=Doe" and " John" — " John" has no '=' so is ignored.
        // CN becomes "Doe" and O becomes "Acme".
        let dn = result.unwrap();
        assert_eq!(dn.common_name, "Doe");
        assert_eq!(dn.organization, Some("Acme".to_string()));
    }

    #[test]
    fn test_dn_cn_with_quotes_via_builder() {
        // Quotes are valid UTF-8 characters in CN
        let dn = NameBuilder::new(r#"The "CA" Root"#)
            .organization("Test")
            .build();
        assert_eq!(dn.common_name, r#"The "CA" Root"#);
        // UTF8String encoding should handle quotes
        let name = dn.to_name().unwrap();
        assert!(!name.0.is_empty());
    }

    #[test]
    fn test_dn_cn_with_quotes_roundtrip_via_x509() {
        let original = NameBuilder::new(r#"The "Root" CA"#)
            .organization("Quoted Org")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.common_name, r#"The "Root" CA"#);
    }

    #[test]
    fn test_rfc2253_with_special_chars_in_values() {
        // Parentheses and apostrophes are legal PrintableString characters
        let dn = DistinguishedName::from_rfc2253("CN=O'Malley's (Root),O=Test,C=US").unwrap();
        assert_eq!(dn.common_name, "O'Malley's (Root)");
        assert_eq!(dn.organization, Some("Test".to_string()));
    }

    #[test]
    fn test_rfc2253_equals_in_value() {
        // split_once('=') means only the first '=' splits key/value
        let dn = DistinguishedName::from_rfc2253("CN=a=b,O=Test,C=US").unwrap();
        assert_eq!(dn.common_name, "a=b");
    }

    #[test]
    fn test_rfc2253_case_insensitive_keys() {
        let dn = DistinguishedName::from_rfc2253("cn=Test,o=Org,c=US,st=Texas").unwrap();
        assert_eq!(dn.common_name, "Test");
        assert_eq!(dn.organization, Some("Org".to_string()));
        assert_eq!(dn.country, Some("US".to_string()));
        assert_eq!(dn.state, Some("Texas".to_string()));
    }

    #[test]
    fn test_rfc2253_missing_cn_fails() {
        let result = DistinguishedName::from_rfc2253("O=Test,C=US");
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("CN"),
            "expected CN-related error, got: {}",
            err
        );
    }

    #[test]
    fn test_from_x509_name_all_fields() {
        let original = NameBuilder::new("Full DN Test")
            .country("US")
            .state("Texas")
            .locality("Austin")
            .organization("Test Org")
            .organizational_unit("PKI")
            .uid("testuser")
            .serial_number("12345")
            .email("test@example.com")
            .domain_component("com")
            .domain_component("example")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.common_name, "Full DN Test");
        assert_eq!(roundtrip.country, Some("US".to_string()));
        assert_eq!(roundtrip.state, Some("Texas".to_string()));
        assert_eq!(roundtrip.locality, Some("Austin".to_string()));
        assert_eq!(roundtrip.organization, Some("Test Org".to_string()));
        assert_eq!(roundtrip.organizational_unit, Some("PKI".to_string()));
        assert_eq!(roundtrip.uid, Some("testuser".to_string()));
        assert_eq!(roundtrip.serial_number, Some("12345".to_string()));
        assert_eq!(roundtrip.email, Some("test@example.com".to_string()));
        assert_eq!(roundtrip.domain_components, vec!["com", "example"]);
    }

    // --- Issue #30: DN parsing with special characters ---

    #[test]
    fn test_dn_cn_with_unicode_via_builder() {
        // UTF-8 characters (accented letters) should encode as UTF8String
        let dn = NameBuilder::new("Zertifikatsstelle Munchen")
            .organization("Stadtwerke")
            .build();
        assert_eq!(dn.common_name, "Zertifikatsstelle Munchen");
        let name = dn.to_name().unwrap();
        assert!(!name.0.is_empty());
    }

    #[test]
    fn test_dn_cn_with_accented_chars_roundtrip() {
        // Accented characters force UTF8String encoding; verify roundtrip
        let original = NameBuilder::new("CA Racine de la Securite")
            .organization("Entreprise Francaise")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.common_name, "CA Racine de la Securite");
        assert_eq!(
            roundtrip.organization,
            Some("Entreprise Francaise".to_string())
        );
    }

    #[test]
    fn test_dn_cn_with_slashes() {
        // Slashes are valid PrintableString characters
        let dn = NameBuilder::new("Root/Intermediate CA")
            .organization("Test/Corp")
            .build();
        let name = dn.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&name).unwrap();
        assert_eq!(roundtrip.common_name, "Root/Intermediate CA");
        assert_eq!(roundtrip.organization, Some("Test/Corp".to_string()));
    }

    #[test]
    fn test_dn_cn_with_colons() {
        // Colons are valid PrintableString characters
        let dn = NameBuilder::new("CA:v2:Primary").build();
        let name = dn.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&name).unwrap();
        assert_eq!(roundtrip.common_name, "CA:v2:Primary");
    }

    #[test]
    fn test_dn_cn_with_plus_sign() {
        // Plus sign is valid in PrintableString
        let dn = NameBuilder::new("Root+Backup CA").build();
        let name = dn.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&name).unwrap();
        assert_eq!(roundtrip.common_name, "Root+Backup CA");
    }

    #[test]
    fn test_dn_cn_with_question_mark() {
        // Question mark is valid PrintableString
        let dn = NameBuilder::new("Test CA?").build();
        let name = dn.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&name).unwrap();
        assert_eq!(roundtrip.common_name, "Test CA?");
    }

    #[test]
    fn test_dn_cn_with_parentheses_and_apostrophe_roundtrip() {
        // Parentheses and apostrophes are PrintableString characters
        let original = NameBuilder::new("O'Brien's (Root) CA")
            .organization("O'Brien Ltd")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.common_name, "O'Brien's (Root) CA");
        assert_eq!(roundtrip.organization, Some("O'Brien Ltd".to_string()));
    }

    #[test]
    fn test_rfc2253_with_extra_whitespace() {
        // Extra whitespace around keys and values should be trimmed
        let dn =
            DistinguishedName::from_rfc2253("  CN = Spaced CA , O = Spaced Org , C=US").unwrap();
        assert_eq!(dn.common_name, "Spaced CA");
        assert_eq!(dn.organization, Some("Spaced Org".to_string()));
        assert_eq!(dn.country, Some("US".to_string()));
    }

    #[test]
    fn test_rfc2253_all_field_aliases() {
        // ST and S both map to State; E, EMAIL, EMAILADDRESS all map to email
        let dn = DistinguishedName::from_rfc2253("CN=Test,S=California,C=US").unwrap();
        assert_eq!(dn.state, Some("California".to_string()));

        let dn2 = DistinguishedName::from_rfc2253("CN=Test2,EMAILADDRESS=admin@example.com,C=US")
            .unwrap();
        assert_eq!(dn2.email, Some("admin@example.com".to_string()));

        let dn3 = DistinguishedName::from_rfc2253("CN=Test3,E=alt@example.com,C=US").unwrap();
        assert_eq!(dn3.email, Some("alt@example.com".to_string()));
    }

    #[test]
    fn test_rfc2253_unknown_attributes_ignored() {
        // Unknown attribute keys should be silently ignored
        let dn = DistinguishedName::from_rfc2253("CN=Test,FOO=bar,TITLE=Director,C=US").unwrap();
        assert_eq!(dn.common_name, "Test");
        assert_eq!(dn.country, Some("US".to_string()));
    }

    #[test]
    fn test_rfc2253_serial_number() {
        let dn = DistinguishedName::from_rfc2253("CN=Device,SERIALNUMBER=SN-123456,C=US").unwrap();
        assert_eq!(dn.serial_number, Some("SN-123456".to_string()));
    }

    #[test]
    fn test_dn_validate_dc_with_null_byte() {
        let mut dn = DistinguishedName::simple("Test");
        dn.domain_components.push("com".to_string());
        dn.domain_components.push("bad\0dc".to_string());
        assert!(dn.validate().is_err());
    }

    #[test]
    fn test_dn_validate_uid_with_null_byte() {
        let result = NameBuilder::new("Test").uid("bad\0user").build_validated();
        assert!(result.is_err());
    }

    #[test]
    fn test_dn_validate_empty_state() {
        let result = NameBuilder::new("Test").state("   ").build_validated();
        assert!(result.is_err());
    }

    #[test]
    fn test_dn_cn_with_equals_sign_roundtrip() {
        // Equals sign is valid in PrintableString — verify X.509 roundtrip
        let original = NameBuilder::new("CN=with=equals").build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.common_name, "CN=with=equals");
    }

    #[test]
    fn test_dn_multi_dc_roundtrip() {
        // Multiple domain components should survive X.509 roundtrip in order
        let original = NameBuilder::new("Root CA")
            .domain_component("com")
            .domain_component("example")
            .domain_component("corp")
            .build();
        let x509_name = original.to_name().unwrap();
        let roundtrip = DistinguishedName::from_x509_name(&x509_name).unwrap();
        assert_eq!(roundtrip.domain_components, vec!["com", "example", "corp"]);
    }

    #[test]
    fn test_rfc2253_userid_alias() {
        let dn = DistinguishedName::from_rfc2253("USERID=jane,CN=Jane Doe,C=US").unwrap();
        assert_eq!(dn.uid, Some("jane".to_string()));
        assert_eq!(dn.common_name, "Jane Doe");
    }

    #[test]
    fn test_dn_cn_max_64_chars_with_special_chars() {
        // CN at exactly 64 characters including special chars should be valid
        let prefix = "A-B/C.D'E(F)G+H,I=J K:L?M";
        let cn = format!("{}{}", prefix, "X".repeat(64 - prefix.len()));
        assert_eq!(cn.len(), 64);
        let result = NameBuilder::new(&cn).build_validated();
        assert!(
            result.is_ok(),
            "64-char CN with special chars should be valid"
        );
    }

    #[test]
    #[allow(unused_imports)]
    fn test_dc_encodes_as_ia5string() {
        // RFC 4519 §2.4: domainComponent MUST be encoded as IA5String
        use der::Encode;
        let dn = DistinguishedName {
            domain_components: vec!["com".into(), "quantumnexum".into()],
            common_name: "Test".into(),
            ..DistinguishedName::simple("Test")
        };
        let der = dn.to_der().unwrap();
        // IA5String tag is 0x16; PrintableString is 0x13; UTF8String is 0x0c
        // DC values should use tag 0x16
        assert!(
            der.windows(4)
                .any(|w| w[0] == 0x16 && w[1] == 3 && &w[2..4] == b"co"),
            "DC='com' should be IA5String (tag 0x16)"
        );
    }

    #[test]
    #[allow(unused_imports)]
    fn test_email_encodes_as_ia5string() {
        // RFC 4519 §2.16: emailAddress MUST be encoded as IA5String
        use der::Encode;
        let mut dn = DistinguishedName::simple("Test");
        dn.email = Some("admin@example.com".into());
        let der = dn.to_der().unwrap();
        // IA5String tag is 0x16; look for the tag followed by "admin"
        assert!(
            der.windows(7).any(|w| w[0] == 0x16 && &w[2..7] == b"admin"),
            "email should be IA5String (tag 0x16)"
        );
    }
}
