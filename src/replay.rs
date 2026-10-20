//! Replay protection for received MIKEY messages (RFC 3830 §5.4).
//!
//! §5.4 builds anti-replay on timestamps rather than a challenge-response:
//!
//! > MIKEY does not use a challenge-response mechanism for replay handling;
//! > instead, timestamps are used. This requires that the clocks are
//! > synchronized. […] Each Responder utilizes a replay cache in order to
//! > remember the successfully authenticated messages presented within an
//! > allowable clock skew (which is set by the local policy).
//!
//! # The caller supplies the clock
//!
//! mykey deliberately does not read the clock. It cannot know the accuracy of
//! the host's time source, and guessing wrong in either direction is harmful:
//! too tight and legitimate messages expire, too loose and a captured message
//! stays replayable.
//!
//! Note that §4.2.8 asks for the NTP *format* — a 64-bit count of seconds since
//! 1900, the same encoding RTCP sender reports use — not the NTP *protocol*. A
//! PTP-locked host can populate it perfectly well, provided it derives a wall
//! clock rather than only a media clock.
//!
//! | Time source | Realistic window |
//! |---|---|
//! | PTP-derived wall clock | sub-second |
//! | NTP on a LAN | tens of seconds |
//! | NTP over a WAN | minutes |
//! | Unsynchronized, or an offline/file-based exchange | replay protection is not available |
//!
//! That last row matters. A MIKEY message written to an SDP file and copied to
//! the receiver later has no live clock relationship between the two ends, so no
//! window is meaningful. Do not pretend otherwise by choosing a large one.
//!
//! # Example
//!
//! ```
//! # extern crate mykey;
//! use std::time::{Duration, SystemTime};
//! use mykey::replay::ReplayCache;
//!
//! // Window chosen from the deployment's clock accuracy, not guessed by mykey.
//! let mut cache = ReplayCache::new(Duration::from_secs(30));
//! assert!(cache.is_empty());
//! # let _ = SystemTime::now();
//! ```

use std::collections::HashMap;
use std::time::{Duration, SystemTime};

use crate::error::{MikeyError, Result};

/// Seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
pub const NTP_UNIX_EPOCH_OFFSET: u64 = 2_208_988_800;

/// Default cap on cached entries.
///
/// §5.4 anticipates overload: "If the host loses track of the incoming requests
/// (e.g., due to overload), it rejects all incoming requests until the clock
/// skew interval has passed." The cap makes that behaviour concrete rather than
/// letting the cache grow without bound under a flood of unique RANDs.
pub const DEFAULT_MAX_ENTRIES: usize = 4096;

/// What [`verify_fresh`](crate::message::MikeyMessage::verify_fresh) was able to
/// check.
///
/// Returned rather than collapsed into `()` so a caller that genuinely requires
/// freshness can tell when it did not get it, instead of silently accepting a
/// weaker guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// The message carried an NTP-format timestamp, it fell inside the window,
    /// and the message had not been seen before.
    Verified,
    /// The message carried a COUNTER timestamp, which is not a clock, so only
    /// replay was checked — not freshness.
    ///
    /// mykey itself still emits COUNTER, so this is the result for a
    /// mykey-to-mykey exchange until NTP-format emission lands. A peer could
    /// replay such a message once the cache has expired its entry.
    ReplayOnly,
}

/// Identity of a message for replay purposes: the CSB ID and the RAND.
///
/// RAND is at least 128 random bits (§4.1.1) and the CSB ID scopes it to a
/// bundle, so the pair identifies an exchange without needing the whole message.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ReplayKey {
    csb_id: u32,
    rand: Vec<u8>,
}

/// A cache of recently seen, successfully authenticated messages.
///
/// Caller-held: mykey keeps no global state, so the lifetime and memory are
/// yours. Memory is bounded by arrival rate × window, up to
/// [`max_entries`](ReplayCache::max_entries).
///
/// The window doubles as the freshness tolerance — they are deliberately one
/// value, since a message older than the window could not be replayed inside it
/// anyway, and two separate knobs could disagree.
pub struct ReplayCache {
    window: Duration,
    max_entries: usize,
    seen: HashMap<ReplayKey, SystemTime>,
}

impl ReplayCache {
    /// Create a cache with the given window, which is also the freshness
    /// tolerance. See the module documentation for choosing it.
    pub fn new(window: Duration) -> Self {
        Self::with_max_entries(window, DEFAULT_MAX_ENTRIES)
    }

    /// Create a cache with an explicit entry cap.
    pub fn with_max_entries(window: Duration, max_entries: usize) -> Self {
        Self {
            window,
            max_entries,
            seen: HashMap::new(),
        }
    }

    /// The configured window, which is also the freshness tolerance.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// The configured entry cap.
    pub fn max_entries(&self) -> usize {
        self.max_entries
    }

    /// Number of entries currently retained.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    /// Drop entries observed longer ago than the window.
    ///
    /// Expiry uses the **local observation time**, not the message's own
    /// timestamp, so it works even when that timestamp is not a clock.
    pub fn prune(&mut self, now: SystemTime) {
        let window = self.window;
        self.seen
            .retain(|_, seen_at| match now.duration_since(*seen_at) {
                Ok(age) => age <= window,
                // Observed "in the future" relative to `now` — the caller's clock
                // stepped backwards. Keep it; it will expire once time passes.
                Err(_) => true,
            });
    }

    /// Record a message, rejecting one already seen.
    ///
    /// Prunes first, so a long-expired entry does not count as a replay.
    fn check_and_insert(&mut self, key: ReplayKey, now: SystemTime) -> Result<()> {
        self.prune(now);

        if self.seen.contains_key(&key) {
            return Err(MikeyError::ReplayDetected);
        }

        // §5.4: reject rather than evict when overloaded, so a flood of unique
        // RANDs cannot push genuine entries out and make replays possible.
        if self.seen.len() >= self.max_entries {
            return Err(MikeyError::ReplayCacheFull);
        }

        self.seen.insert(key, now);
        Ok(())
    }

    /// Check a message's identity and timestamp against the cache.
    ///
    /// `ntp_timestamp` is the raw T payload value when it is an NTP-format
    /// (64-bit) timestamp, or `None` for a COUNTER, which cannot be checked for
    /// freshness.
    pub(crate) fn admit(
        &mut self,
        csb_id: u32,
        rand: &[u8],
        ntp_timestamp: Option<&[u8]>,
        now: SystemTime,
    ) -> Result<Freshness> {
        let freshness = match ntp_timestamp {
            Some(bytes) => {
                let ts = ntp_to_system_time(bytes)?;
                if skew(ts, now) > self.window {
                    return Err(MikeyError::StaleTimestamp);
                }
                Freshness::Verified
            }
            None => Freshness::ReplayOnly,
        };

        self.check_and_insert(
            ReplayKey {
                csb_id,
                rand: rand.to_vec(),
            },
            now,
        )?;

        Ok(freshness)
    }
}

/// Absolute difference between two instants.
///
/// A message may legitimately appear slightly in the future when the peer's
/// clock runs ahead, so the window is two-sided.
fn skew(a: SystemTime, b: SystemTime) -> Duration {
    match a.duration_since(b) {
        Ok(d) => d,
        Err(e) => e.duration(),
    }
}

/// Convert a 64-bit NTP-format timestamp (§4.2.8) to a [`SystemTime`].
///
/// The upper 32 bits are seconds since 1900-01-01 and the lower 32 are a binary
/// fraction of a second.
pub fn ntp_to_system_time(bytes: &[u8]) -> Result<SystemTime> {
    if bytes.len() != 8 {
        return Err(MikeyError::Parse(format!(
            "NTP timestamp must be 8 bytes, got {}",
            bytes.len()
        )));
    }

    let secs_1900 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
    let frac = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]) as u64;

    // Timestamps before the Unix epoch cannot be represented; §4.2.8 also warns
    // that the 32-bit second count rolls over around 2036, which this does not
    // yet attempt to disambiguate.
    let unix_secs = secs_1900
        .checked_sub(NTP_UNIX_EPOCH_OFFSET)
        .ok_or_else(|| MikeyError::Parse("NTP timestamp precedes the Unix epoch".into()))?;

    // frac / 2^32 of a second, in nanoseconds.
    let nanos = (frac * 1_000_000_000) >> 32;

    Ok(SystemTime::UNIX_EPOCH + Duration::new(unix_secs, nanos as u32))
}

/// Render a [`SystemTime`] as a 64-bit NTP-format timestamp (§4.2.8).
pub fn system_time_to_ntp(t: SystemTime) -> Result<[u8; 8]> {
    let since_epoch = t
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| MikeyError::Crypto("time precedes the Unix epoch".into()))?;

    let secs_1900 = since_epoch
        .as_secs()
        .checked_add(NTP_UNIX_EPOCH_OFFSET)
        .ok_or_else(|| MikeyError::Crypto("timestamp overflows the NTP epoch".into()))?;

    let mut out = [0u8; 8];
    // Truncating to 32 bits is the documented §4.2.8 rollover.
    out[..4].copy_from_slice(&(secs_1900 as u32).to_be_bytes());
    let frac = ((since_epoch.subsec_nanos() as u64) << 32) / 1_000_000_000;
    out[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(secs: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn test_ntp_roundtrip() {
        for secs in [0u64, 1, 1_000_000, 1_700_000_000] {
            let t = at(secs);
            let bytes = system_time_to_ntp(t).unwrap();
            let back = ntp_to_system_time(&bytes).unwrap();
            assert_eq!(back, t, "roundtrip at {secs}");
        }
    }

    /// The NTP epoch is 70 years before the Unix epoch; a Unix-epoch timestamp
    /// must encode as exactly that offset.
    #[test]
    fn test_ntp_epoch_offset_is_correct() {
        let bytes = system_time_to_ntp(SystemTime::UNIX_EPOCH).unwrap();
        let secs = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64;
        assert_eq!(secs, NTP_UNIX_EPOCH_OFFSET);
        assert_eq!(
            NTP_UNIX_EPOCH_OFFSET, 2_208_988_800,
            "70 years incl. leap days"
        );
    }

    #[test]
    fn test_ntp_subsecond_precision_survives() {
        let t = SystemTime::UNIX_EPOCH + Duration::new(1_700_000_000, 500_000_000);
        let back = ntp_to_system_time(&system_time_to_ntp(t).unwrap()).unwrap();
        let err = skew(back, t);
        // 1/2^32 s ≈ 233 ps, so a nanosecond of slack is ample.
        assert!(err <= Duration::from_nanos(1), "lost precision: {err:?}");
    }

    #[test]
    fn test_ntp_wrong_length_rejected() {
        assert!(ntp_to_system_time(&[0u8; 4]).is_err());
        assert!(ntp_to_system_time(&[0u8; 9]).is_err());
    }

    #[test]
    fn test_replay_rejected_within_window() {
        let mut cache = ReplayCache::new(Duration::from_secs(30));
        let now = at(1_700_000_000);
        let rand = [0xAAu8; 16];

        assert_eq!(
            cache.admit(1, &rand, None, now).unwrap(),
            Freshness::ReplayOnly
        );
        assert!(matches!(
            cache.admit(1, &rand, None, now),
            Err(MikeyError::ReplayDetected)
        ));
    }

    #[test]
    fn test_distinct_messages_both_admitted() {
        let mut cache = ReplayCache::new(Duration::from_secs(30));
        let now = at(1_700_000_000);

        cache.admit(1, &[0xAAu8; 16], None, now).unwrap();
        // Different RAND, same CSB.
        cache.admit(1, &[0xBBu8; 16], None, now).unwrap();
        // Same RAND, different CSB — the key is the pair.
        cache.admit(2, &[0xAAu8; 16], None, now).unwrap();
        assert_eq!(cache.len(), 3);
    }

    #[test]
    fn test_entries_expire_and_memory_is_bounded() {
        let mut cache = ReplayCache::new(Duration::from_secs(10));
        let t0 = at(1_700_000_000);
        cache.admit(1, &[0xAAu8; 16], None, t0).unwrap();
        assert_eq!(cache.len(), 1);

        // Past the window: the entry is dropped, so the same message is
        // admissible again. That is the documented limit of a bounded cache.
        let later = t0 + Duration::from_secs(11);
        cache.admit(1, &[0xAAu8; 16], None, later).unwrap();
        assert_eq!(
            cache.len(),
            1,
            "the stale entry was pruned, not accumulated"
        );
    }

    #[test]
    fn test_stale_timestamp_rejected_both_directions() {
        let mut cache = ReplayCache::new(Duration::from_secs(5));
        let now = at(1_700_000_000);

        // Too old.
        let old = system_time_to_ntp(now - Duration::from_secs(60)).unwrap();
        assert!(matches!(
            cache.admit(1, &[1u8; 16], Some(&old), now),
            Err(MikeyError::StaleTimestamp)
        ));

        // Too far in the future — the window is two-sided.
        let future = system_time_to_ntp(now + Duration::from_secs(60)).unwrap();
        assert!(matches!(
            cache.admit(1, &[2u8; 16], Some(&future), now),
            Err(MikeyError::StaleTimestamp)
        ));

        // Inside the window, and reported as actually verified.
        let good = system_time_to_ntp(now + Duration::from_secs(2)).unwrap();
        assert_eq!(
            cache.admit(1, &[3u8; 16], Some(&good), now).unwrap(),
            Freshness::Verified
        );
    }

    /// A rejected message must not be recorded, or an attacker could poison the
    /// cache against a legitimate retransmission.
    #[test]
    fn test_stale_message_is_not_cached() {
        let mut cache = ReplayCache::new(Duration::from_secs(5));
        let now = at(1_700_000_000);
        let old = system_time_to_ntp(now - Duration::from_secs(60)).unwrap();

        assert!(cache.admit(1, &[1u8; 16], Some(&old), now).is_err());
        assert!(cache.is_empty(), "a rejected message must not be retained");
    }

    /// §5.4: reject under overload rather than evicting, so a flood of unique
    /// RANDs cannot push out genuine entries and re-enable replays.
    #[test]
    fn test_cache_full_rejects_rather_than_evicting() {
        let mut cache = ReplayCache::with_max_entries(Duration::from_secs(60), 3);
        let now = at(1_700_000_000);

        for i in 0..3u8 {
            cache.admit(1, &[i; 16], None, now).unwrap();
        }
        assert!(matches!(
            cache.admit(1, &[99u8; 16], None, now),
            Err(MikeyError::ReplayCacheFull)
        ));

        // The earliest entry is still protected against replay.
        assert!(matches!(
            cache.admit(1, &[0u8; 16], None, now),
            Err(MikeyError::ReplayDetected)
        ));
    }

    /// A backwards step in the caller's clock must not silently empty the cache.
    #[test]
    fn test_backwards_clock_step_retains_entries() {
        let mut cache = ReplayCache::new(Duration::from_secs(30));
        let now = at(1_700_000_000);
        cache.admit(1, &[0xAAu8; 16], None, now).unwrap();

        cache.prune(now - Duration::from_secs(3600));
        assert_eq!(
            cache.len(),
            1,
            "entries must survive a backwards clock step"
        );
    }
}
