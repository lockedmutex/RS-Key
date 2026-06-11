// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The legacy YubiKey OTP HID frame protocol: a 70-byte frame (64-byte payload
//! ‖ slot ‖ CRC ‖ pad) carried 7 payload bytes per 8-byte FEATURE report, written
//! via SET_REPORT and polled via GET_REPORT — the transport `ykman otp` speaks.

use crate::crc16;

/// HID feature-report size.
pub const REPORT_SIZE: usize = 8;
/// Payload bytes per report — the 8th byte is the flag/sequence field.
pub const REPORT_DATA: usize = REPORT_SIZE - 1;
/// Reassembled frame: 64-byte payload ‖ slot ‖ CRC(2) ‖ pad(3) = 70.
pub const FRAME_SIZE: usize = 70;
/// Command payload size.
pub const PAYLOAD_SIZE: usize = 64;

/// Host→device flag: a data frame (the low 5 bits are the sequence number).
const FLAG_WRITE: u8 = 0x80;
/// Device→host flag: a response frame is pending / present.
const FLAG_RESP_PENDING: u8 = 0x40;
/// Host→device sentinel byte that resets the transfer state.
const FLAG_RESET: u8 = 0xFF;
const SEQ_MASK: u8 = 0x1F;

/// What a host feature report did to the [`FrameRx`] state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RxOutcome {
    /// Mid-frame, or a report that carried no actionable change.
    None,
    /// The host asked to reset the transfer (clear any pending response).
    Reset,
    /// A complete, CRC-valid frame: run `slot_id` with `payload` as the APDU.
    Frame {
        slot: u8,
        payload: [u8; PAYLOAD_SIZE],
    },
    /// A complete frame whose CRC did not match — dropped.
    BadCrc,
}

/// Reassembles the 10 sequenced feature reports of one host frame.
///
/// Report byte 7 is `0xFF` (reset) or `0x80 | seq` for a data slice. Slice
/// `seq` lands at offset `seq*7`; the final slice (`seq == 9`) completes the
/// 70-byte frame, whose stored CRC (a plain CRC-16 over the 64-byte payload) is
/// checked before the frame is released.
pub struct FrameRx {
    buf: [u8; FRAME_SIZE],
}

impl Default for FrameRx {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameRx {
    pub const fn new() -> Self {
        Self {
            buf: [0; FRAME_SIZE],
        }
    }

    /// Consume one 8-byte feature report.
    pub fn feed(&mut self, report: &[u8; REPORT_SIZE]) -> RxOutcome {
        let flag = report[REPORT_DATA];
        if flag == FLAG_RESET {
            self.buf = [0; FRAME_SIZE];
            return RxOutcome::Reset;
        }
        if flag & FLAG_WRITE == 0 {
            return RxOutcome::None;
        }
        let seq = (flag & SEQ_MASK) as usize;
        if seq > 9 {
            return RxOutcome::None;
        }
        if seq == 0 {
            self.buf = [0; FRAME_SIZE];
        }
        self.buf[seq * REPORT_DATA..seq * REPORT_DATA + REPORT_DATA]
            .copy_from_slice(&report[..REPORT_DATA]);
        if seq != 9 {
            return RxOutcome::None;
        }
        // Final slice: validate the frame CRC (plain CRC-16 over the payload).
        let want = u16::from_le_bytes([self.buf[65], self.buf[66]]);
        if crc16(&self.buf[..PAYLOAD_SIZE]) != want {
            return RxOutcome::BadCrc;
        }
        let mut payload = [0u8; PAYLOAD_SIZE];
        payload.copy_from_slice(&self.buf[..PAYLOAD_SIZE]);
        RxOutcome::Frame {
            slot: self.buf[PAYLOAD_SIZE],
            payload,
        }
    }
}

/// Slices a response body back to the host across feature reports.
///
/// The body is suffixed with the complement of its CRC-16 (so the host's
/// payload-plus-CRC check lands on the X.25 residual), then served 7 bytes per
/// report tagged `0x40 | seq` (response-pending), finished by a lone `0x40`
/// end marker.
pub struct FrameTx {
    buf: [u8; FRAME_SIZE + 2],
    remaining: usize,
    seq: u8,
    expected: u8,
}

impl Default for FrameTx {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameTx {
    pub const fn new() -> Self {
        Self {
            buf: [0; FRAME_SIZE + 2],
            remaining: 0,
            seq: 0,
            expected: 0,
        }
    }

    /// Whether a response is still being streamed.
    pub fn active(&self) -> bool {
        self.remaining > 0 || self.expected > 0
    }

    /// Load a response body (≤ 64 bytes); the CRC suffix is appended here.
    pub fn load(&mut self, body: &[u8]) {
        let n = body.len().min(PAYLOAD_SIZE);
        self.buf = [0; FRAME_SIZE + 2];
        self.buf[..n].copy_from_slice(&body[..n]);
        let crc = !crc16(&body[..n]);
        self.buf[n..n + 2].copy_from_slice(&crc.to_le_bytes());
        let total = n + 2;
        self.remaining = total;
        self.expected = total.div_ceil(REPORT_DATA) as u8;
        self.seq = 0;
    }

    /// Fill the next 8-byte response report. Returns `false` once the stream is
    /// drained (the caller then serves the status frame).
    pub fn next(&mut self, out: &mut [u8; REPORT_SIZE]) -> bool {
        if self.remaining > 0 {
            let off = self.seq as usize * REPORT_DATA;
            let n = self.remaining.min(REPORT_DATA);
            *out = [0; REPORT_SIZE];
            out[..n].copy_from_slice(&self.buf[off..off + n]);
            out[REPORT_DATA] = FLAG_RESP_PENDING | self.seq;
            self.remaining -= n;
            self.seq += 1;
            true
        } else if self.expected > 0 && self.seq == self.expected {
            // End-of-response marker: pending bit set, sequence bits zero.
            *out = [0; REPORT_SIZE];
            out[REPORT_DATA] = FLAG_RESP_PENDING;
            self.seq = 0;
            self.expected = 0;
            true
        } else {
            false
        }
    }
}

/// The 8-byte status frame served by an idle GET_REPORT:
/// `status` (= [`crate::OtpApplet::status_bytes`]) prefixed by a reserved byte.
pub fn status_frame(status: [u8; 7]) -> [u8; REPORT_SIZE] {
    [
        0, status[0], status[1], status[2], status[3], status[4], status[5], status[6],
    ]
}

/// Frame one host command for [`FrameRx`] testing/fuzzing: split a 64-byte
/// `payload` + `slot` into the 10 sequenced 8-byte reports (with the plain frame
/// CRC), matching `yubikit.core.otp._format_frame`.
pub fn split_frame(payload: &[u8; PAYLOAD_SIZE], slot: u8) -> [[u8; REPORT_SIZE]; 10] {
    let mut frame = [0u8; FRAME_SIZE];
    frame[..PAYLOAD_SIZE].copy_from_slice(payload);
    frame[PAYLOAD_SIZE] = slot;
    let crc = crc16(payload);
    frame[65..67].copy_from_slice(&crc.to_le_bytes());
    let mut reports = [[0u8; REPORT_SIZE]; 10];
    for (seq, rep) in reports.iter_mut().enumerate() {
        rep[..REPORT_DATA]
            .copy_from_slice(&frame[seq * REPORT_DATA..seq * REPORT_DATA + REPORT_DATA]);
        rep[REPORT_DATA] = FLAG_WRITE | seq as u8;
    }
    reports
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reassembles_a_full_frame() {
        let mut payload = [0u8; PAYLOAD_SIZE];
        for (i, b) in payload.iter_mut().enumerate() {
            *b = i as u8;
        }
        let reports = split_frame(&payload, 0x30);
        let mut rx = FrameRx::new();
        for r in &reports[..9] {
            assert_eq!(rx.feed(r), RxOutcome::None);
        }
        match rx.feed(&reports[9]) {
            RxOutcome::Frame { slot, payload: p } => {
                assert_eq!(slot, 0x30);
                assert_eq!(p, payload);
            }
            other => panic!("expected Frame, got {other:?}"),
        }
    }

    #[test]
    fn rejects_corrupted_crc() {
        let payload = [0xAAu8; PAYLOAD_SIZE];
        let mut reports = split_frame(&payload, 1);
        reports[9][0] ^= 0xFF; // corrupt the last payload slice
        let mut rx = FrameRx::new();
        for r in &reports[..9] {
            rx.feed(r);
        }
        assert_eq!(rx.feed(&reports[9]), RxOutcome::BadCrc);
    }

    #[test]
    fn reset_byte_clears_state() {
        let mut rx = FrameRx::new();
        let mut reset = [0u8; REPORT_SIZE];
        reset[REPORT_DATA] = FLAG_RESET;
        assert_eq!(rx.feed(&reset), RxOutcome::Reset);
    }

    #[test]
    fn out_of_range_sequence_ignored() {
        let mut rx = FrameRx::new();
        let mut bad = [0u8; REPORT_SIZE];
        bad[REPORT_DATA] = FLAG_WRITE | 0x0A; // seq 10
        assert_eq!(rx.feed(&bad), RxOutcome::None);
    }

    #[test]
    fn tx_streams_body_then_end_marker_and_host_crc_checks() {
        // A 20-byte response (an HMAC-SHA1 chal-resp) → 22 bytes with CRC → 4
        // data frames (7+7+7+1) + an end marker.
        let body: Vec<u8> = (0..20u8).collect();
        let mut tx = FrameTx::new();
        tx.load(&body);
        let mut got = Vec::new();
        let mut seqs = Vec::new();
        let mut out = [0u8; REPORT_SIZE];
        while tx.next(&mut out) {
            if out[REPORT_DATA] & SEQ_MASK == 0 && got.len() >= 22 {
                break; // end marker
            }
            got.extend_from_slice(&out[..REPORT_DATA]);
            seqs.push(out[REPORT_DATA]);
        }
        assert_eq!(seqs, [0x40, 0x41, 0x42, 0x43]);
        // The host validates payload ‖ CRC against the X.25 residual.
        assert_eq!(&got[..20], &body[..]);
        assert_eq!(crc16(&got[..22]), 0xF0B8);
        assert!(!tx.active());
    }

    #[test]
    fn status_frame_layout() {
        let s = status_frame([5, 7, 4, 3, 0x01, 0, 0]);
        assert_eq!(s, [0, 5, 7, 4, 3, 0x01, 0, 0]);
    }
}
