//! Validate an A response for the fixed example.com probe question.
use std::collections::BTreeSet;

fn name(data: &[u8], start: usize) -> Option<(String, usize)> {
    let mut offset = start;
    let mut end = None;
    let mut labels = Vec::new();
    let mut steps = 0;
    loop {
        steps += 1;
        if steps > 128 {
            return None;
        }
        let length = *data.get(offset)?;
        if length == 0 {
            return Some((
                labels.join(".").to_ascii_lowercase(),
                end.unwrap_or(offset + 1),
            ));
        }
        if length & 0xc0 == 0xc0 {
            let next = *data.get(offset + 1)?;
            let pointer = (((length & 0x3f) as usize) << 8) | next as usize;
            if pointer >= data.len() {
                return None;
            }
            if end.is_none() {
                end = Some(offset + 2);
            }
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        let next = offset.checked_add(1 + length as usize)?;
        let label = data.get(offset + 1..next)?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_graphic() && *byte != b'.')
        {
            return None;
        }
        labels.push(std::str::from_utf8(label).ok()?.to_owned());
        if labels.iter().map(|item| item.len() + 1).sum::<usize>() > 254 {
            return None;
        }
        offset = next;
    }
}
fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(at)?, *data.get(at + 1)?]))
}
pub(crate) fn valid(data: &[u8], id: [u8; 2]) -> bool {
    (|| {
        if data.len() < 12
            || data[..2] != id
            || data[2] & 0x80 == 0
            || data[2] & 0x78 != 0
            || data[2] & 0x02 != 0
            || data[3] & 0x0f != 0
            || read_u16(data, 4)? != 1
        {
            return None;
        }
        let answers = read_u16(data, 6)? as usize;
        if answers == 0 || answers > 64 {
            return None;
        }
        let (question, mut offset) = name(data, 12)?;
        if question != "example.com"
            || read_u16(data, offset)? != 1
            || read_u16(data, offset + 2)? != 1
        {
            return None;
        }
        offset = offset.checked_add(4)?;
        let mut addresses = BTreeSet::new();
        let mut aliases = Vec::new();
        for _ in 0..answers {
            let (owner, next) = name(data, offset)?;
            offset = next;
            let kind = read_u16(data, offset)?;
            let class = read_u16(data, offset + 2)?;
            let length = read_u16(data, offset + 8)? as usize;
            let start = offset.checked_add(10)?;
            let end = start.checked_add(length)?;
            data.get(start..end)?;
            if class == 1 && kind == 1 && length == 4 {
                addresses.insert(owner.clone());
            }
            if class == 1 && kind == 5 {
                let (target, next) = name(data, start)?;
                if next != end {
                    return None;
                }
                aliases.push((owner, target));
            }
            offset = end;
        }
        let mut pending = vec!["example.com".to_owned()];
        let mut seen = BTreeSet::new();
        while let Some(current) = pending.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if addresses.contains(&current) {
                return Some(());
            }
            pending.extend(
                aliases
                    .iter()
                    .filter(|(owner, _)| owner == &current)
                    .map(|(_, target)| target.clone()),
            );
        }
        None
    })()
    .is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn question() -> Vec<u8> {
        let mut data = vec![1, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        data.extend_from_slice(b"\x07example\x03com\x00\x00\x01\x00\x01");
        data
    }
    #[test]
    fn requires_a_matching_complete_answer_and_rejects_pointer_loops() {
        let mut data = question();
        assert!(!valid(&data, [1, 2]));
        data.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1]);
        assert!(valid(&data, [1, 2]));
        assert!(!valid(&data, [2, 1]));
        let end = data.len();
        data.truncate(end - 1);
        assert!(!valid(&data, [1, 2]));
        let mut looped = question();
        looped.extend_from_slice(&[0xc0, 0x1d, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1]);
        assert!(!valid(&looped, [1, 2]));
    }
    #[test]
    fn accepts_a_valid_cname_chain() {
        let mut data = question();
        data[7] = 2;
        data.extend_from_slice(&[
            0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 8, 5, b'a', b'l', b'i', b'a', b's', 0xc0, 0x0c,
        ]);
        data.extend_from_slice(&[
            5, b'a', b'l', b'i', b'a', b's', 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 1, 1, 1,
        ]);
        assert!(valid(&data, [1, 2]));
    }
}
