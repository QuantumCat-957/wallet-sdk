pub(crate) fn derivation_path_percent_encode(
    raw_derivation_path: &str,
) -> percent_encoding::PercentEncode {
    percent_encoding::percent_encode(
        raw_derivation_path.as_bytes(),
        percent_encoding::NON_ALPHANUMERIC,
    )
}

pub(crate) fn derivation_path_percent_decode(
    encoded_derivation_path: &str,
) -> percent_encoding::PercentDecode {
    percent_encoding::percent_decode_str(&encoded_derivation_path)
}
