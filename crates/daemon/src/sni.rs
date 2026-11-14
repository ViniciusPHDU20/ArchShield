pub fn extract_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 44 || payload[0] != 0x16 || payload[5] != 0x01 {
        return None;
    }

    let session_id_len = payload[43] as usize;
    let mut pos = 44 + session_id_len;
    if pos + 2 > payload.len() {
        return None;
    }

    let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2 + cipher_suites_len;
    if pos + 1 > payload.len() {
        return None;
    }

    let comp_methods_len = payload[pos] as usize;
    pos += 1 + comp_methods_len;
    if pos + 2 > payload.len() {
        return None;
    }

    let extensions_len = u16::from_be_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + extensions_len).min(payload.len());

    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([payload[pos], payload[pos + 1]]);
        let ext_len = u16::from_be_bytes([payload[pos + 2], payload[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0 {
            // SNI Extension
            if pos + 5 <= payload.len() {
                let sni_len = u16::from_be_bytes([payload[pos + 3], payload[pos + 4]]) as usize;
                if pos + 5 + sni_len <= payload.len() {
                    return String::from_utf8(payload[pos + 5..pos + 5 + sni_len].to_vec()).ok();
                }
            }
        }
        pos += ext_len;
    }

    None
}
