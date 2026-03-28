use tokio::net::TcpStream;

/// Extract the SNI (Server Name Indication) hostname from a TLS ClientHello
/// by peeking at the stream without consuming data.
pub async fn extract_sni(stream: &TcpStream) -> Option<String> {
    let mut buf = [0u8; 4096];
    let n = stream.peek(&mut buf).await.ok()?;
    parse_sni(&buf[..n])
}

/// Parse SNI from raw TLS ClientHello bytes.
fn parse_sni(buf: &[u8]) -> Option<String> {
    // TLS record header: content_type(1) + version(2) + length(2)
    if buf.len() < 5 {
        return None;
    }
    // content_type must be Handshake (0x16)
    if buf[0] != 0x16 {
        return None;
    }

    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record = buf.get(5..5 + record_len)?;

    // Handshake header: type(1) + length(3)
    if record.is_empty() || record[0] != 0x01 {
        // Must be ClientHello
        return None;
    }
    let handshake_len =
        ((record[1] as usize) << 16) | ((record[2] as usize) << 8) | (record[3] as usize);
    let hello = record.get(4..4 + handshake_len)?;

    // ClientHello: version(2) + random(32) = skip 34 bytes
    if hello.len() < 34 {
        return None;
    }
    let mut pos = 34;

    // Session ID: length(1) + data
    let session_id_len = *hello.get(pos)? as usize;
    pos += 1 + session_id_len;

    // Cipher suites: length(2) + data
    let cs_len = u16::from_be_bytes([*hello.get(pos)?, *hello.get(pos + 1)?]) as usize;
    pos += 2 + cs_len;

    // Compression methods: length(1) + data
    let comp_len = *hello.get(pos)? as usize;
    pos += 1 + comp_len;

    // Extensions: length(2) + data
    if pos + 2 > hello.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
    pos += 2;

    let ext_end = pos + ext_len;
    while pos + 4 <= ext_end && pos + 4 <= hello.len() {
        let ext_type = u16::from_be_bytes([hello[pos], hello[pos + 1]]);
        let ext_data_len = u16::from_be_bytes([hello[pos + 2], hello[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // SNI extension
            return parse_sni_extension(hello.get(pos..pos + ext_data_len)?);
        }
        pos += ext_data_len;
    }

    None
}

/// Parse the SNI extension data to extract the hostname.
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    // ServerNameList: length(2) + entries
    if data.len() < 2 {
        return None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let list = data.get(2..2 + list_len)?;

    let mut pos = 0;
    while pos + 3 <= list.len() {
        let name_type = list[pos];
        let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
        pos += 3;

        if name_type == 0x00 {
            // host_name type
            let name_bytes = list.get(pos..pos + name_len)?;
            return String::from_utf8(name_bytes.to_vec()).ok();
        }
        pos += name_len;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        // SNI extension data
        let name_bytes = hostname.as_bytes();
        let sni_entry_len = 3 + name_bytes.len(); // type(1) + len(2) + name
        let sni_list_len = sni_entry_len;
        let sni_ext_data_len = 2 + sni_list_len; // list_len(2) + list

        let mut sni_ext = Vec::new();
        // Extension type: SNI (0x0000)
        sni_ext.extend_from_slice(&[0x00, 0x00]);
        // Extension data length
        sni_ext.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        // ServerNameList length
        sni_ext.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
        // Name type: host_name (0)
        sni_ext.push(0x00);
        // Name length
        sni_ext.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        // Name
        sni_ext.extend_from_slice(name_bytes);

        let extensions_len = sni_ext.len();

        // ClientHello body
        let mut hello = Vec::new();
        // Version (TLS 1.2)
        hello.extend_from_slice(&[0x03, 0x03]);
        // Random (32 bytes)
        hello.extend_from_slice(&[0u8; 32]);
        // Session ID length: 0
        hello.push(0x00);
        // Cipher suites: length 2, one suite
        hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]);
        // Compression methods: length 1, null
        hello.extend_from_slice(&[0x01, 0x00]);
        // Extensions length
        hello.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        // Extensions data
        hello.extend_from_slice(&sni_ext);

        let handshake_len = hello.len();

        // Handshake header
        let mut handshake = vec![
            0x01, // Type: ClientHello
            ((handshake_len >> 16) & 0xff) as u8,
            ((handshake_len >> 8) & 0xff) as u8,
            (handshake_len & 0xff) as u8,
        ];
        handshake.extend_from_slice(&hello);

        let record_len = handshake.len();

        // TLS record header
        let mut record = Vec::new();
        // Content type: Handshake (0x16)
        record.push(0x16);
        // Version (TLS 1.0 in record layer)
        record.extend_from_slice(&[0x03, 0x01]);
        // Length
        record.extend_from_slice(&(record_len as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        record
    }

    #[test]
    fn test_extract_sni_basic() {
        let data = build_client_hello("example.com");
        assert_eq!(parse_sni(&data), Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sni_subdomain() {
        let data = build_client_hello("www.google.com");
        assert_eq!(parse_sni(&data), Some("www.google.com".to_string()));
    }

    #[test]
    fn test_extract_sni_long_hostname() {
        let data = build_client_hello("very.long.subdomain.example.co.uk");
        assert_eq!(
            parse_sni(&data),
            Some("very.long.subdomain.example.co.uk".to_string())
        );
    }

    #[test]
    fn test_no_sni_on_non_tls() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(parse_sni(data), None);
    }

    #[test]
    fn test_no_sni_on_empty() {
        assert_eq!(parse_sni(&[]), None);
    }

    #[test]
    fn test_no_sni_on_truncated() {
        let data = build_client_hello("example.com");
        // Truncate mid-extensions
        assert_eq!(parse_sni(&data[..data.len() / 2]), None);
    }

    #[test]
    fn test_no_sni_wrong_content_type() {
        let mut data = build_client_hello("example.com");
        data[0] = 0x17; // Change to ApplicationData
        assert_eq!(parse_sni(&data), None);
    }
}
