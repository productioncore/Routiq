//! Minimal SSE (Server-Sent Events) frame parser for the control-plane
//! `/config/stream` change stream.
//!
//! Wire format per frame (fields end at the first blank line):
//! ```text
//! id: 105
//! event: config_changed
//! data: {"revision":105,...}
//!
//! :comment lines and unknown fields are ignored.
//! ```
//!
//! The parser is incremental: feed it the growing buffer, it drains complete
//! frames and keeps the partial tail.

/// A parsed SSE frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    /// Numeric `id:` when present (our revision carrier).
    pub id: Option<u64>,
    /// `event:` type, defaults to `"message"`.
    pub event: String,
    /// Joined `data:` lines.
    pub data: String,
}

/// Revision decision for an incoming `config_changed` revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevisionDecision {
    /// `received <= current` — duplicate or stale, ignore.
    Ignore,
    /// `received > current` — snapshot-fetch then apply (covers both the
    /// next revision and gaps; the fetch is the reconciliation mechanism,
    /// so we never blind-apply metadata).
    Fetch,
}

/// Decide what to do with an incoming revision given the active one.
pub fn decide_revision(current: u64, received: u64) -> RevisionDecision {
    if received > current {
        RevisionDecision::Fetch
    } else {
        RevisionDecision::Ignore
    }
}

fn parse_frame(block: &str) -> Option<SseEvent> {
    let mut id: Option<u64> = None;
    let mut event = "message".to_string();
    let mut data_lines: Vec<&str> = Vec::new();
    let mut saw_field = false;

    for raw_line in block.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.starts_with(':') {
            continue; // comment / heartbeat (:hug)
        }
        saw_field = true;
        let (field, value) = match line.find(':') {
            Some(i) => (&line[..i], line[i + 1..].trim_start()),
            None => (line, ""),
        };
        match field {
            "id" => {
                if let Ok(n) = value.parse::<u64>() {
                    id = Some(n);
                }
            }
            "event" => {
                if !value.is_empty() {
                    event = value.to_string();
                }
            }
            "data" => data_lines.push(value),
            "retry" => {} // server reconnect hint — informational here
            _ => {}       // forward-compatible: ignore unknown fields
        }
    }

    if !saw_field {
        return None;
    }
    // Transport-only frames (`retry:`, bare comments) carry no event type
    // and no data — skip them silently instead of dispatching noise.
    if event == "message" && data_lines.is_empty() {
        return None;
    }
    Some(SseEvent {
        id,
        event,
        data: data_lines.join("\n"),
    })
}

/// End offset (past the terminator) of the first complete frame, accepting
/// both `\n\n` and `\r\n\r\n` terminators.
fn frame_end(buf: &str) -> Option<usize> {
    let lf = buf.find("\n\n").map(|i| i + 2);
    let crlf = buf.find("\r\n\r\n").map(|i| i + 4);
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Drain complete frames from `buf`, keeping the partial tail for the next
/// read. Returns parsed events in wire order.
pub fn drain_frames(buf: &mut String) -> Vec<SseEvent> {
    let mut events = Vec::new();
    loop {
        let end = match frame_end(buf) {
            Some(i) => i,
            None => break,
        };
        let block: String = buf.drain(..end).collect();
        if let Some(ev) = parse_frame(block.trim_end_matches(['\n', '\r'])) {
            events.push(ev);
        }
    }
    events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_config_changed_frame() {
        let mut buf = "id: 105\nevent: config_changed\ndata: {\"revision\":105}\n\n".to_string();
        let events = drain_frames(&mut buf);
        assert_eq!(buf, "");
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some(105));
        assert_eq!(events[0].event, "config_changed");
        assert_eq!(events[0].data, "{\"revision\":105}");
    }

    #[test]
    fn keeps_partial_tail_across_reads() {
        let mut buf = "id: 10".to_string();
        assert!(drain_frames(&mut buf).is_empty());
        buf.push_str("5\nevent: config_changed\ndata: {}\n\n");
        let events = drain_frames(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, Some(105));
    }

    #[test]
    fn skips_retry_only_frames_silently() {
        let mut buf = "retry: 10000\n\n".to_string();
        assert!(drain_frames(&mut buf).is_empty());
        assert_eq!(buf, "");
    }

    #[test]
    fn ignores_comments_and_unknown_fields() {
        let mut buf = ":heartbeat\nfoo: bar\nretry: 5000\nevent: heartbeat\ndata: {\"ts\":1}\n\n".to_string();
        let events = drain_frames(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event, "heartbeat");
        assert_eq!(events[0].id, None);
    }

    #[test]
    fn joins_multiline_data_and_handles_crlf() {
        let mut buf = "event: x\r\ndata: a\r\ndata: b\r\n\r\n".to_string();
        let events = drain_frames(&mut buf);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].data, "a\nb");
    }

    #[test]
    fn multiple_frames_in_one_read() {
        let mut buf = "event: a\ndata: 1\n\nevent: b\ndata: 2\n\n".to_string();
        let events = drain_frames(&mut buf);
        assert_eq!(events.len(), 2);
        assert_eq!(events[1].event, "b");
    }

    #[test]
    fn revision_decisions() {
        assert_eq!(decide_revision(104, 102), RevisionDecision::Ignore); // stale
        assert_eq!(decide_revision(104, 104), RevisionDecision::Ignore); // duplicate
        assert_eq!(decide_revision(104, 105), RevisionDecision::Fetch); // next
        assert_eq!(decide_revision(104, 106), RevisionDecision::Fetch); // gap → fetch (reconcile)
        assert_eq!(decide_revision(0, 1), RevisionDecision::Fetch); // boot
    }
}
