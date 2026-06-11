// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors

//! The `Applet` trait plus AID-based SELECT and APDU dispatch.

use zeroize::Zeroize;

use crate::apdu::Apdu;
use crate::sw::Sw;

/// A response buffer an applet writes its RAPDU body into. The status word is
/// appended by the dispatcher.
pub struct ResBuf<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl<'a> ResBuf<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        ResBuf { buf, len: 0 }
    }
    pub fn clear(&mut self) {
        self.len = 0;
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
    /// Append one byte; returns false if the buffer is full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.len < self.buf.len() {
            self.buf[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }
    /// Append a slice; returns false (and writes nothing) if it would overflow.
    pub fn extend(&mut self, data: &[u8]) -> bool {
        if self.len + data.len() <= self.buf.len() {
            self.buf[self.len..self.len + data.len()].copy_from_slice(data);
            self.len += data.len();
            true
        } else {
            false
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// A selectable smartcard applet.
///
/// `C` is a shared context (the file system in `firmware`) the dispatcher threads
/// into every call, so applets hold no `static mut` device state.
pub trait Applet<C> {
    /// The application identifier, without a length prefix. SELECT matches when
    /// this is a prefix of the requested AID.
    fn aid(&self) -> &'static [u8];
    /// Called on SELECT. `reselect` is true when this applet was already current.
    /// `res` receives the SELECT response body (e.g. an OpenPGP FCI); leave it
    /// empty for applets that return no data.
    fn select(&mut self, reselect: bool, ctx: &mut C, res: &mut ResBuf) -> Sw;
    /// Handle a non-SELECT command APDU.
    fn process(&mut self, apdu: &Apdu, ctx: &mut C, res: &mut ResBuf) -> Sw;
    /// Called when another applet is selected.
    fn deselect(&mut self, _ctx: &mut C) {}
}

const CHAIN_BUF_SIZE: usize = 2038;

/// Routes APDUs to applets: SELECT-by-AID, command chaining (CLA bit 0x10),
/// and dispatch to the current applet.
pub struct Dispatcher {
    current: Option<usize>,
    chaining: bool,
    chain: [u8; CHAIN_BUF_SIZE],
    chain_len: usize,
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Dispatcher {
    pub const fn new() -> Self {
        Dispatcher {
            current: None,
            chaining: false,
            chain: [0u8; CHAIN_BUF_SIZE],
            chain_len: 0,
        }
    }

    /// Index of the currently selected applet, if any.
    pub fn current(&self) -> Option<usize> {
        self.current
    }

    /// Process one raw command APDU against `applets` (in registration order),
    /// threading the shared `ctx` into the dispatched applet, writing the
    /// response body into `res` and returning the status word.
    pub fn process<C>(
        &mut self,
        raw: &[u8],
        applets: &mut [&mut dyn Applet<C>],
        ctx: &mut C,
        res: &mut ResBuf,
    ) -> Sw {
        res.clear();
        let apdu = match Apdu::parse(raw) {
            Ok(a) => a,
            Err(_) => return Sw::WRONG_LENGTH,
        };

        // Command chaining: accumulate and acknowledge.
        if apdu.is_chaining() {
            if !self.chaining {
                self.chain_len = 0;
            }
            if self.chain_len + apdu.nc >= self.chain.len() {
                // The accumulated segments may already hold key material.
                self.chain[..self.chain_len].zeroize();
                self.chain_len = 0;
                self.chaining = false;
                return Sw::CLA_NOT_SUPPORTED;
            }
            self.chain[self.chain_len..self.chain_len + apdu.nc].copy_from_slice(apdu.data);
            self.chain_len += apdu.nc;
            self.chaining = true;
            return Sw::OK;
        }
        // A non-chained APDU after chaining segments is the final one: append its
        // data and dispatch the reassembled command (needed by OpenPGP RSA IMPORT,
        // whose extended header list exceeds 255 bytes). Chained commands always
        // target the current applet — SELECT is never chained.
        if self.chaining {
            if self.chain_len + apdu.nc > self.chain.len() {
                self.chain[..self.chain_len].zeroize();
                self.chain_len = 0;
                self.chaining = false;
                return Sw::WRONG_LENGTH;
            }
            self.chain[self.chain_len..self.chain_len + apdu.nc].copy_from_slice(apdu.data);
            let total = self.chain_len + apdu.nc;
            self.chaining = false;
            self.chain_len = 0;
            let combined = Apdu {
                cla: apdu.cla,
                ins: apdu.ins,
                p1: apdu.p1,
                p2: apdu.p2,
                nc: total,
                ne: apdu.ne,
                data: &self.chain[..total],
            };
            let sw = match self.current {
                Some(i) => applets[i].process(&combined, ctx, res),
                None => Sw::FILE_NOT_FOUND,
            };
            // A chained command can carry private-key IMPORT data.
            self.chain[..total].zeroize();
            return sw;
        }

        // SELECT by AID.
        if apdu.ins == 0xA4 && apdu.p1 == 0x04 && (apdu.p2 == 0x00 || apdu.p2 == 0x04) {
            let found = applets.iter().position(|app| {
                let aid = app.aid();
                apdu.data.len() >= aid.len() && &apdu.data[..aid.len()] == aid
            });
            return match found {
                Some(i) => {
                    let reselect = self.current == Some(i);
                    if let Some(c) = self.current
                        && c != i
                    {
                        applets[c].deselect(ctx);
                    }
                    self.current = Some(i);
                    applets[i].select(reselect, ctx, res)
                }
                None => Sw::FILE_NOT_FOUND,
            };
        }

        // Dispatch to the selected applet.
        match self.current {
            Some(i) => applets[i].process(&apdu, ctx, res),
            None => Sw::FILE_NOT_FOUND,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo {
        selected: bool,
    }
    // Context-free applet: the unit type stands in for "no file system".
    impl Applet<()> for Echo {
        fn aid(&self) -> &'static [u8] {
            &[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]
        }
        fn select(&mut self, _reselect: bool, _ctx: &mut (), _res: &mut ResBuf) -> Sw {
            self.selected = true;
            Sw::OK
        }
        fn process(&mut self, apdu: &Apdu, _ctx: &mut (), res: &mut ResBuf) -> Sw {
            if apdu.ins == 0x10 {
                res.extend(apdu.data);
                Sw::OK
            } else {
                Sw::INS_NOT_SUPPORTED
            }
        }
    }

    #[test]
    fn select_then_dispatch() {
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);

        // Unknown command before any selection.
        assert_eq!(
            disp.process(&[0x00, 0x10, 0, 0], &mut applets, &mut (), &mut res),
            Sw::FILE_NOT_FOUND
        );

        // SELECT by AID.
        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
        assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);
        assert_eq!(disp.current(), Some(0));

        // Now an echo command.
        let cmd = [0x00, 0x10, 0x00, 0x00, 0x03, 0xDE, 0xAD, 0xBE];
        assert_eq!(disp.process(&cmd, &mut applets, &mut (), &mut res), Sw::OK);
        assert_eq!(res.as_slice(), &[0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn command_chaining_reassembles() {
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 64];
        let mut res = ResBuf::new(&mut out);

        let mut sel = vec![0x00, 0xA4, 0x04, 0x00, 0x08];
        sel.extend_from_slice(&[0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01]);
        assert_eq!(disp.process(&sel, &mut applets, &mut (), &mut res), Sw::OK);

        // Two chaining segments (CLA bit 0x10) are acknowledged with no body…
        assert_eq!(
            disp.process(
                &[0x10, 0x10, 0, 0, 0x02, 0xAA, 0xBB],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );
        assert!(res.is_empty());
        assert_eq!(
            disp.process(
                &[0x10, 0x10, 0, 0, 0x02, 0xCC, 0xDD],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );
        // …then the final non-chained segment dispatches the reassembled command.
        assert_eq!(
            disp.process(
                &[0x00, 0x10, 0, 0, 0x01, 0xEE],
                &mut applets,
                &mut (),
                &mut res
            ),
            Sw::OK
        );
        assert_eq!(res.as_slice(), &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn select_unknown_aid() {
        let mut echo = Echo { selected: false };
        let mut applets: [&mut dyn Applet<()>; 1] = [&mut echo];
        let mut disp = Dispatcher::new();
        let mut out = [0u8; 16];
        let mut res = ResBuf::new(&mut out);
        let sel = [0x00, 0xA4, 0x04, 0x00, 0x02, 0x12, 0x34];
        assert_eq!(
            disp.process(&sel, &mut applets, &mut (), &mut res),
            Sw::FILE_NOT_FOUND
        );
    }
}
