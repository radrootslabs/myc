//! Allocation-bounded structural admission for encrypted NIP-46 events and plaintext requests.

use core::fmt;
use std::error::Error;

use radroots_nostr_connect::{
    message::{
        REQUEST_ID_MAX_BYTES, REQUEST_PARAM_COUNT_MAX, REQUEST_PARAM_MAX_BYTES,
        REQUEST_PARAMS_MAX_BYTES,
    },
    method::METHOD_MAX_BYTES,
};
use serde::Deserialize;
use serde::de::{self, DeserializeSeed, IgnoredAny, SeqAccess, Visitor};
use serde_json::value::RawValue;

use crate::MycConfigDocumentV1;

/// Maximum encoded Nostr event identifier length admitted before event parsing.
pub const MYC_NIP46_EVENT_ID_MAX_BYTES: usize = 64;

/// Maximum encoded Nostr public-key length admitted before event parsing.
pub const MYC_NIP46_PUBLIC_KEY_MAX_BYTES: usize = 64;

/// Maximum encoded Nostr signature length admitted before event parsing.
pub const MYC_NIP46_SIGNATURE_MAX_BYTES: usize = 128;

const TAG_COUNT_SENTINEL: &str = "myc-tag-count-limit";
const TAG_ELEMENT_COUNT_SENTINEL: &str = "myc-tag-element-count-limit";
const TAG_ELEMENT_BYTES_SENTINEL: &str = "myc-tag-element-bytes-limit";
const TAG_TOTAL_BYTES_SENTINEL: &str = "myc-tag-total-bytes-limit";
const PARAM_COUNT_SENTINEL: &str = "myc-param-count-limit";
const PARAM_BYTES_SENTINEL: &str = "myc-param-bytes-limit";
const PARAM_TOTAL_BYTES_SENTINEL: &str = "myc-param-total-bytes-limit";

/// Immutable limits projected from one admitted Myc configuration document.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycNip46AdmissionLimits {
    event_wire_bytes: usize,
    event_content_bytes: usize,
    event_tag_count: usize,
    event_tag_total_elements: usize,
    event_tag_element_bytes: usize,
    event_tag_total_bytes: usize,
    decrypted_plaintext_bytes: usize,
}

impl MycNip46AdmissionLimits {
    /// Projects the exact event limits from a validated immutable configuration.
    pub fn from_config(
        configuration: &MycConfigDocumentV1,
    ) -> Result<Self, MycNip46AdmissionError> {
        Ok(Self {
            event_wire_bytes: config_limit(configuration, "/resource_limits/events/wire_bytes")?,
            event_content_bytes: config_limit(
                configuration,
                "/resource_limits/events/content_bytes",
            )?,
            event_tag_count: config_limit(configuration, "/resource_limits/events/tag_count")?,
            event_tag_total_elements: config_limit(
                configuration,
                "/resource_limits/events/tag_total_elements",
            )?,
            event_tag_element_bytes: config_limit(
                configuration,
                "/resource_limits/events/tag_element_bytes",
            )?,
            event_tag_total_bytes: config_limit(
                configuration,
                "/resource_limits/events/tag_total_bytes",
            )?,
            decrypted_plaintext_bytes: config_limit(
                configuration,
                "/resource_limits/events/decrypted_plaintext_bytes",
            )?,
        })
    }

    /// Returns the original event-wire byte cap.
    #[must_use]
    pub const fn event_wire_bytes(self) -> usize {
        self.event_wire_bytes
    }

    /// Returns the decoded event-content byte cap.
    #[must_use]
    pub const fn event_content_bytes(self) -> usize {
        self.event_content_bytes
    }

    /// Returns the outer event-tag count cap.
    #[must_use]
    pub const fn event_tag_count(self) -> usize {
        self.event_tag_count
    }

    /// Returns the aggregate tag-element count cap.
    #[must_use]
    pub const fn event_tag_total_elements(self) -> usize {
        self.event_tag_total_elements
    }

    /// Returns the decoded byte cap for one tag element.
    #[must_use]
    pub const fn event_tag_element_bytes(self) -> usize {
        self.event_tag_element_bytes
    }

    /// Returns the aggregate decoded tag-element byte cap.
    #[must_use]
    pub const fn event_tag_total_bytes(self) -> usize {
        self.event_tag_total_bytes
    }

    /// Returns the decrypted NIP-46 plaintext byte cap.
    #[must_use]
    pub const fn decrypted_plaintext_bytes(self) -> usize {
        self.decrypted_plaintext_bytes
    }
}

impl fmt::Debug for MycNip46AdmissionLimits {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46AdmissionLimits")
            .field("event_wire_bytes", &self.event_wire_bytes)
            .field("event_content_bytes", &self.event_content_bytes)
            .field("event_tag_count", &self.event_tag_count)
            .field("event_tag_total_elements", &self.event_tag_total_elements)
            .field("event_tag_element_bytes", &self.event_tag_element_bytes)
            .field("event_tag_total_bytes", &self.event_tag_total_bytes)
            .field("decrypted_plaintext_bytes", &self.decrypted_plaintext_bytes)
            .finish()
    }
}

/// Stable source-free classification for NIP-46 resource-admission failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MycNip46AdmissionErrorKind {
    InvalidLimits,
    EmptyEvent,
    EventTooLarge,
    InvalidEventUtf8,
    MalformedEvent,
    EventIdentifierTooLarge,
    EventContentTooLarge,
    TooManyTags,
    TooManyTagElements,
    TagElementTooLarge,
    TagsTooLarge,
    EmptyPlaintext,
    PlaintextTooLarge,
    InvalidPlaintextUtf8,
    MalformedRequest,
    RequestIdentifierTooLarge,
    RequestMethodTooLarge,
    TooManyRequestParameters,
    RequestParameterTooLarge,
    RequestParametersTooLarge,
}

impl MycNip46AdmissionErrorKind {
    const fn message(self) -> &'static str {
        match self {
            Self::InvalidLimits => "NIP-46 admission limits are invalid",
            Self::EmptyEvent => "NIP-46 event bytes are empty",
            Self::EventTooLarge => "NIP-46 event exceeds its wire limit",
            Self::InvalidEventUtf8 => "NIP-46 event is not valid UTF-8",
            Self::MalformedEvent => "NIP-46 event structure is invalid",
            Self::EventIdentifierTooLarge => "NIP-46 event identifier exceeds its limit",
            Self::EventContentTooLarge => "NIP-46 event content exceeds its limit",
            Self::TooManyTags => "NIP-46 event tag count exceeds its limit",
            Self::TooManyTagElements => "NIP-46 event tag elements exceed their count limit",
            Self::TagElementTooLarge => "NIP-46 event tag element exceeds its byte limit",
            Self::TagsTooLarge => "NIP-46 event tags exceed their aggregate byte limit",
            Self::EmptyPlaintext => "NIP-46 request plaintext is empty",
            Self::PlaintextTooLarge => "NIP-46 request plaintext exceeds its limit",
            Self::InvalidPlaintextUtf8 => "NIP-46 request plaintext is not valid UTF-8",
            Self::MalformedRequest => "NIP-46 request structure is invalid",
            Self::RequestIdentifierTooLarge => "NIP-46 request identifier exceeds its limit",
            Self::RequestMethodTooLarge => "NIP-46 request method exceeds its limit",
            Self::TooManyRequestParameters => "NIP-46 request parameter count exceeds its limit",
            Self::RequestParameterTooLarge => "NIP-46 request parameter exceeds its byte limit",
            Self::RequestParametersTooLarge => {
                "NIP-46 request parameters exceed their aggregate byte limit"
            }
        }
    }
}

/// One redacted NIP-46 resource-admission failure.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct MycNip46AdmissionError {
    kind: MycNip46AdmissionErrorKind,
}

impl MycNip46AdmissionError {
    const fn new(kind: MycNip46AdmissionErrorKind) -> Self {
        Self { kind }
    }

    /// Returns the stable failure classification.
    #[must_use]
    pub const fn kind(self) -> MycNip46AdmissionErrorKind {
        self.kind
    }
}

impl fmt::Debug for MycNip46AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycNip46AdmissionError")
            .field("kind", &self.kind)
            .finish()
    }
}

impl fmt::Display for MycNip46AdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.kind.message())
    }
}

impl Error for MycNip46AdmissionError {}

/// One structurally admitted encrypted NIP-46 event.
pub struct MycBoundedNip46Event {
    original: Box<[u8]>,
    encrypted_content: Box<str>,
    tag_count: usize,
    tag_element_count: usize,
    tag_bytes: usize,
}

impl MycBoundedNip46Event {
    /// Returns the exact original event bytes retained for later verification.
    #[must_use]
    pub fn original_bytes(&self) -> &[u8] {
        &self.original
    }

    /// Returns the bounded ciphertext without decrypting it.
    #[must_use]
    pub fn encrypted_content(&self) -> &str {
        &self.encrypted_content
    }

    /// Returns the number of admitted tags.
    #[must_use]
    pub const fn tag_count(&self) -> usize {
        self.tag_count
    }

    /// Returns the aggregate number of admitted tag elements.
    #[must_use]
    pub const fn tag_element_count(&self) -> usize {
        self.tag_element_count
    }

    /// Returns the aggregate decoded UTF-8 bytes in all tag elements.
    #[must_use]
    pub const fn tag_bytes(&self) -> usize {
        self.tag_bytes
    }
}

impl fmt::Debug for MycBoundedNip46Event {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycBoundedNip46Event")
            .field("wire_bytes", &self.original.len())
            .field("content_bytes", &self.encrypted_content.len())
            .field("tag_count", &self.tag_count)
            .field("tag_element_count", &self.tag_element_count)
            .field("tag_bytes", &self.tag_bytes)
            .finish()
    }
}

/// One structurally admitted decrypted NIP-46 request.
pub struct MycBoundedNip46Request {
    plaintext: Box<[u8]>,
    request_id_bytes: usize,
    method_bytes: usize,
    parameter_count: usize,
    parameter_bytes: usize,
}

impl MycBoundedNip46Request {
    /// Returns the admitted plaintext byte count without exposing its content.
    #[must_use]
    pub fn plaintext_bytes(&self) -> usize {
        self.plaintext.len()
    }

    /// Returns the decoded request-identifier byte count.
    #[must_use]
    pub const fn request_id_bytes(&self) -> usize {
        self.request_id_bytes
    }

    /// Returns the decoded request-method byte count.
    #[must_use]
    pub const fn method_bytes(&self) -> usize {
        self.method_bytes
    }

    /// Returns the admitted request-parameter count.
    #[must_use]
    pub const fn parameter_count(&self) -> usize {
        self.parameter_count
    }

    /// Returns aggregate decoded UTF-8 bytes in request parameters.
    #[must_use]
    pub const fn parameter_bytes(&self) -> usize {
        self.parameter_bytes
    }
}

impl fmt::Debug for MycBoundedNip46Request {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MycBoundedNip46Request")
            .field("plaintext_bytes", &self.plaintext.len())
            .field("request_id_bytes", &self.request_id_bytes)
            .field("method_bytes", &self.method_bytes)
            .field("parameter_count", &self.parameter_count)
            .field("parameter_bytes", &self.parameter_bytes)
            .finish()
    }
}

/// Bounds and structurally admits original encrypted event bytes before decryption.
pub fn admit_myc_nip46_event(
    limits: MycNip46AdmissionLimits,
    original: &[u8],
) -> Result<MycBoundedNip46Event, MycNip46AdmissionError> {
    if original.is_empty() {
        return Err(failure(MycNip46AdmissionErrorKind::EmptyEvent));
    }
    if original.len() > limits.event_wire_bytes {
        return Err(failure(MycNip46AdmissionErrorKind::EventTooLarge));
    }
    let source = std::str::from_utf8(original)
        .map_err(|_| failure(MycNip46AdmissionErrorKind::InvalidEventUtf8))?;
    let raw: RawEvent<'_> = parse_exact(source, MycNip46AdmissionErrorKind::MalformedEvent)?;

    validate_bounded_string(
        raw.id,
        MYC_NIP46_EVENT_ID_MAX_BYTES,
        MycNip46AdmissionErrorKind::EventIdentifierTooLarge,
        MycNip46AdmissionErrorKind::MalformedEvent,
    )?;
    validate_bounded_string(
        raw.pubkey,
        MYC_NIP46_PUBLIC_KEY_MAX_BYTES,
        MycNip46AdmissionErrorKind::EventIdentifierTooLarge,
        MycNip46AdmissionErrorKind::MalformedEvent,
    )?;
    validate_bounded_string(
        raw.sig,
        MYC_NIP46_SIGNATURE_MAX_BYTES,
        MycNip46AdmissionErrorKind::EventIdentifierTooLarge,
        MycNip46AdmissionErrorKind::MalformedEvent,
    )?;
    parse_scalar::<u64>(raw.created_at, MycNip46AdmissionErrorKind::MalformedEvent)?;
    parse_scalar::<u64>(raw.kind, MycNip46AdmissionErrorKind::MalformedEvent)?;
    let encrypted_content = decode_bounded_string(
        raw.content,
        limits.event_content_bytes,
        MycNip46AdmissionErrorKind::EventContentTooLarge,
        MycNip46AdmissionErrorKind::MalformedEvent,
    )?;
    let tags = measure_tags(raw.tags, limits)?;

    Ok(MycBoundedNip46Event {
        original: original.into(),
        encrypted_content: encrypted_content.into_boxed_str(),
        tag_count: tags.count,
        tag_element_count: tags.elements,
        tag_bytes: tags.bytes,
    })
}

/// Bounds and structurally admits decrypted request bytes before typed decoding.
pub fn admit_myc_nip46_request(
    limits: MycNip46AdmissionLimits,
    plaintext: &[u8],
) -> Result<MycBoundedNip46Request, MycNip46AdmissionError> {
    if plaintext.is_empty() {
        return Err(failure(MycNip46AdmissionErrorKind::EmptyPlaintext));
    }
    if plaintext.len() > limits.decrypted_plaintext_bytes {
        return Err(failure(MycNip46AdmissionErrorKind::PlaintextTooLarge));
    }
    let source = std::str::from_utf8(plaintext)
        .map_err(|_| failure(MycNip46AdmissionErrorKind::InvalidPlaintextUtf8))?;
    let raw: RawRequest<'_> = parse_exact(source, MycNip46AdmissionErrorKind::MalformedRequest)?;
    let request_id_bytes = validate_bounded_string(
        raw.id,
        REQUEST_ID_MAX_BYTES,
        MycNip46AdmissionErrorKind::RequestIdentifierTooLarge,
        MycNip46AdmissionErrorKind::MalformedRequest,
    )?;
    let method_bytes = validate_bounded_string(
        raw.method,
        METHOD_MAX_BYTES,
        MycNip46AdmissionErrorKind::RequestMethodTooLarge,
        MycNip46AdmissionErrorKind::MalformedRequest,
    )?;
    let parameters = measure_parameters(raw.params)?;

    Ok(MycBoundedNip46Request {
        plaintext: plaintext.into(),
        request_id_bytes,
        method_bytes,
        parameter_count: parameters.count,
        parameter_bytes: parameters.bytes,
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEvent<'a> {
    #[serde(borrow)]
    id: &'a RawValue,
    #[serde(borrow)]
    pubkey: &'a RawValue,
    #[serde(borrow)]
    created_at: &'a RawValue,
    #[serde(borrow)]
    kind: &'a RawValue,
    #[serde(borrow)]
    tags: &'a RawValue,
    #[serde(borrow)]
    content: &'a RawValue,
    #[serde(borrow)]
    sig: &'a RawValue,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRequest<'a> {
    #[serde(borrow)]
    id: &'a RawValue,
    #[serde(borrow)]
    method: &'a RawValue,
    #[serde(borrow)]
    params: &'a RawValue,
}

#[derive(Clone, Copy)]
struct Measurement {
    count: usize,
    elements: usize,
    bytes: usize,
}

fn config_limit(
    configuration: &MycConfigDocumentV1,
    pointer: &str,
) -> Result<usize, MycNip46AdmissionError> {
    configuration
        .normalized()
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or_else(|| failure(MycNip46AdmissionErrorKind::InvalidLimits))
}

fn parse_exact<'a, T>(
    source: &'a str,
    malformed: MycNip46AdmissionErrorKind,
) -> Result<T, MycNip46AdmissionError>
where
    T: Deserialize<'a>,
{
    let mut deserializer = serde_json::Deserializer::from_str(source);
    let value = T::deserialize(&mut deserializer).map_err(|_| failure(malformed))?;
    deserializer.end().map_err(|_| failure(malformed))?;
    Ok(value)
}

fn parse_scalar<T>(
    raw: &RawValue,
    malformed: MycNip46AdmissionErrorKind,
) -> Result<T, MycNip46AdmissionError>
where
    T: serde::de::DeserializeOwned,
{
    serde_json::from_str(raw.get()).map_err(|_| failure(malformed))
}

fn validate_bounded_string(
    raw: &RawValue,
    maximum: usize,
    too_large: MycNip46AdmissionErrorKind,
    malformed: MycNip46AdmissionErrorKind,
) -> Result<usize, MycNip46AdmissionError> {
    let length = decoded_json_string_utf8_bytes(raw.get()).ok_or_else(|| failure(malformed))?;
    if length > maximum {
        return Err(failure(too_large));
    }
    Ok(length)
}

fn decode_bounded_string(
    raw: &RawValue,
    maximum: usize,
    too_large: MycNip46AdmissionErrorKind,
    malformed: MycNip46AdmissionErrorKind,
) -> Result<String, MycNip46AdmissionError> {
    validate_bounded_string(raw, maximum, too_large, malformed)?;
    serde_json::from_str(raw.get()).map_err(|_| failure(malformed))
}

fn decoded_json_string_utf8_bytes(raw: &str) -> Option<usize> {
    let bytes = raw.as_bytes();
    if bytes.len() < 2 || bytes.first() != Some(&b'"') || bytes.last() != Some(&b'"') {
        return None;
    }
    let end = bytes.len() - 1;
    let mut index = 1;
    let mut length = 0usize;
    while index < end {
        let byte = bytes[index];
        if byte == b'\\' {
            index = index.checked_add(1)?;
            let escaped = *bytes.get(index)?;
            match escaped {
                b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't' => {
                    length = length.checked_add(1)?;
                    index = index.checked_add(1)?;
                }
                b'u' => {
                    let first = parse_hex_u16(bytes.get(index + 1..index + 5)?)?;
                    index = index.checked_add(5)?;
                    let scalar = if (0xd800..=0xdbff).contains(&first) {
                        if bytes.get(index..index + 2)? != b"\\u" {
                            return None;
                        }
                        let second = parse_hex_u16(bytes.get(index + 2..index + 6)?)?;
                        if !(0xdc00..=0xdfff).contains(&second) {
                            return None;
                        }
                        index = index.checked_add(6)?;
                        0x1_0000
                            + ((u32::from(first) - 0xd800) << 10)
                            + (u32::from(second) - 0xdc00)
                    } else if (0xdc00..=0xdfff).contains(&first) {
                        return None;
                    } else {
                        u32::from(first)
                    };
                    length = length.checked_add(char::from_u32(scalar)?.len_utf8())?;
                }
                _ => return None,
            }
        } else if byte < 0x80 {
            if byte < 0x20 || byte == b'"' {
                return None;
            }
            length = length.checked_add(1)?;
            index = index.checked_add(1)?;
        } else {
            let character = raw.get(index..end)?.chars().next()?;
            let width = character.len_utf8();
            length = length.checked_add(width)?;
            index = index.checked_add(width)?;
        }
    }
    (index == end).then_some(length)
}

fn parse_hex_u16(bytes: &[u8]) -> Option<u16> {
    if bytes.len() != 4 {
        return None;
    }
    bytes.iter().try_fold(0u16, |value, byte| {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a') + 10,
            b'A'..=b'F' => u16::from(byte - b'A') + 10,
            _ => return None,
        };
        value.checked_mul(16)?.checked_add(digit)
    })
}

fn measure_tags(
    raw: &RawValue,
    limits: MycNip46AdmissionLimits,
) -> Result<Measurement, MycNip46AdmissionError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    let result = TagsSeed { limits }.deserialize(&mut deserializer);
    let measurement = result.map_err(classify_tag_error)?;
    deserializer
        .end()
        .map_err(|_| failure(MycNip46AdmissionErrorKind::MalformedEvent))?;
    Ok(measurement)
}

struct TagsSeed {
    limits: MycNip46AdmissionLimits,
}

impl<'de> DeserializeSeed<'de> for TagsSeed {
    type Value = Measurement;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(TagsVisitor {
            limits: self.limits,
        })
    }
}

struct TagsVisitor {
    limits: MycNip46AdmissionLimits,
}

impl<'de> Visitor<'de> for TagsVisitor {
    type Value = Measurement;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded array of Nostr tags")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result = Measurement {
            count: 0,
            elements: 0,
            bytes: 0,
        };
        while result.count < self.limits.event_tag_count {
            let remaining_elements = self
                .limits
                .event_tag_total_elements
                .checked_sub(result.elements)
                .ok_or_else(|| de::Error::custom(TAG_ELEMENT_COUNT_SENTINEL))?;
            let Some(tag) = sequence.next_element_seed(TagSeed {
                maximum_elements: remaining_elements,
                maximum_element_bytes: self.limits.event_tag_element_bytes,
            })?
            else {
                return Ok(result);
            };
            result.count += 1;
            result.elements = result
                .elements
                .checked_add(tag.elements)
                .ok_or_else(|| de::Error::custom(TAG_ELEMENT_COUNT_SENTINEL))?;
            result.bytes = result
                .bytes
                .checked_add(tag.bytes)
                .ok_or_else(|| de::Error::custom(TAG_TOTAL_BYTES_SENTINEL))?;
            if result.bytes > self.limits.event_tag_total_bytes {
                return Err(de::Error::custom(TAG_TOTAL_BYTES_SENTINEL));
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(TAG_COUNT_SENTINEL));
        }
        Ok(result)
    }
}

struct TagSeed {
    maximum_elements: usize,
    maximum_element_bytes: usize,
}

impl<'de> DeserializeSeed<'de> for TagSeed {
    type Value = Measurement;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(TagVisitor {
            maximum_elements: self.maximum_elements,
            maximum_element_bytes: self.maximum_element_bytes,
        })
    }
}

struct TagVisitor {
    maximum_elements: usize,
    maximum_element_bytes: usize,
}

impl<'de> Visitor<'de> for TagVisitor {
    type Value = Measurement;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded Nostr tag")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result = Measurement {
            count: 1,
            elements: 0,
            bytes: 0,
        };
        while result.elements < self.maximum_elements {
            let Some(length) = sequence.next_element_seed(StringLengthSeed {
                maximum: self.maximum_element_bytes,
                sentinel: TAG_ELEMENT_BYTES_SENTINEL,
            })?
            else {
                return Ok(result);
            };
            result.elements += 1;
            result.bytes = result
                .bytes
                .checked_add(length)
                .ok_or_else(|| de::Error::custom(TAG_TOTAL_BYTES_SENTINEL))?;
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(TAG_ELEMENT_COUNT_SENTINEL));
        }
        Ok(result)
    }
}

fn measure_parameters(raw: &RawValue) -> Result<Measurement, MycNip46AdmissionError> {
    let mut deserializer = serde_json::Deserializer::from_str(raw.get());
    let result = StringSequenceSeed {
        maximum_count: REQUEST_PARAM_COUNT_MAX,
        maximum_element_bytes: REQUEST_PARAM_MAX_BYTES,
        maximum_total_bytes: REQUEST_PARAMS_MAX_BYTES,
        count_sentinel: PARAM_COUNT_SENTINEL,
        element_sentinel: PARAM_BYTES_SENTINEL,
        total_sentinel: PARAM_TOTAL_BYTES_SENTINEL,
    }
    .deserialize(&mut deserializer);
    let measurement = result.map_err(classify_param_error)?;
    deserializer
        .end()
        .map_err(|_| failure(MycNip46AdmissionErrorKind::MalformedRequest))?;
    Ok(measurement)
}

struct StringSequenceSeed {
    maximum_count: usize,
    maximum_element_bytes: usize,
    maximum_total_bytes: usize,
    count_sentinel: &'static str,
    element_sentinel: &'static str,
    total_sentinel: &'static str,
}

impl<'de> DeserializeSeed<'de> for StringSequenceSeed {
    type Value = Measurement;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(StringSequenceVisitor { seed: self })
    }
}

struct StringSequenceVisitor {
    seed: StringSequenceSeed,
}

impl<'de> Visitor<'de> for StringSequenceVisitor {
    type Value = Measurement;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded array of strings")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut result = Measurement {
            count: 0,
            elements: 0,
            bytes: 0,
        };
        while result.count < self.seed.maximum_count {
            let Some(length) = sequence.next_element_seed(StringLengthSeed {
                maximum: self.seed.maximum_element_bytes,
                sentinel: self.seed.element_sentinel,
            })?
            else {
                return Ok(result);
            };
            result.count += 1;
            result.elements = result.count;
            result.bytes = result
                .bytes
                .checked_add(length)
                .ok_or_else(|| de::Error::custom(self.seed.total_sentinel))?;
            if result.bytes > self.seed.maximum_total_bytes {
                return Err(de::Error::custom(self.seed.total_sentinel));
            }
        }
        if sequence.next_element::<IgnoredAny>()?.is_some() {
            return Err(de::Error::custom(self.seed.count_sentinel));
        }
        Ok(result)
    }
}

struct StringLengthSeed {
    maximum: usize,
    sentinel: &'static str,
}

impl<'de> DeserializeSeed<'de> for StringLengthSeed {
    type Value = usize;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = <&RawValue>::deserialize(deserializer)?;
        let length = decoded_json_string_utf8_bytes(raw.get())
            .ok_or_else(|| de::Error::invalid_type(de::Unexpected::Other("non-string"), &self))?;
        if length > self.maximum {
            return Err(de::Error::custom(self.sentinel));
        }
        Ok(length)
    }
}

impl de::Expected for StringLengthSeed {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON string")
    }
}

fn classify_tag_error(error: serde_json::Error) -> MycNip46AdmissionError {
    let rendered = error.to_string();
    let kind = if rendered.contains(TAG_COUNT_SENTINEL) {
        MycNip46AdmissionErrorKind::TooManyTags
    } else if rendered.contains(TAG_ELEMENT_COUNT_SENTINEL) {
        MycNip46AdmissionErrorKind::TooManyTagElements
    } else if rendered.contains(TAG_ELEMENT_BYTES_SENTINEL) {
        MycNip46AdmissionErrorKind::TagElementTooLarge
    } else if rendered.contains(TAG_TOTAL_BYTES_SENTINEL) {
        MycNip46AdmissionErrorKind::TagsTooLarge
    } else {
        MycNip46AdmissionErrorKind::MalformedEvent
    };
    failure(kind)
}

fn classify_param_error(error: serde_json::Error) -> MycNip46AdmissionError {
    let rendered = error.to_string();
    let kind = if rendered.contains(PARAM_COUNT_SENTINEL) {
        MycNip46AdmissionErrorKind::TooManyRequestParameters
    } else if rendered.contains(PARAM_BYTES_SENTINEL) {
        MycNip46AdmissionErrorKind::RequestParameterTooLarge
    } else if rendered.contains(PARAM_TOTAL_BYTES_SENTINEL) {
        MycNip46AdmissionErrorKind::RequestParametersTooLarge
    } else {
        MycNip46AdmissionErrorKind::MalformedRequest
    };
    failure(kind)
}

const fn failure(kind: MycNip46AdmissionErrorKind) -> MycNip46AdmissionError {
    MycNip46AdmissionError::new(kind)
}

#[cfg(test)]
mod tests {
    use super::{MycNip46AdmissionErrorKind, RawValue, measure_parameters};

    fn raw_parameters(lengths: &[usize]) -> Box<RawValue> {
        let encoded = serde_json::to_string(
            &lengths
                .iter()
                .map(|length| "x".repeat(*length))
                .collect::<Vec<_>>(),
        )
        .expect("parameter JSON");
        RawValue::from_string(encoded).expect("raw parameter JSON")
    }

    #[test]
    fn request_parameter_aggregate_bound_is_exact_and_independent() {
        let exact = raw_parameters(&[65_536, 65_536, 65_536, 65_536]);
        let measurement = measure_parameters(&exact).expect("exact aggregate bound");
        assert_eq!(measurement.count, 4);
        assert_eq!(measurement.bytes, 262_144);

        let over = raw_parameters(&[65_536, 65_536, 65_536, 65_536, 1]);
        let error = match measure_parameters(&over) {
            Ok(_) => panic!("over aggregate bound must fail"),
            Err(error) => error,
        };
        assert_eq!(
            error.kind(),
            MycNip46AdmissionErrorKind::RequestParametersTooLarge
        );
    }
}
