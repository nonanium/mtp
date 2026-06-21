// Communication types used in the MTP protocol.
// The numeric values are part of the on‑wire format.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CommunicationType {
    ping = 0x0001,
    message_send = 0x0002,
    update = 0x0003,
}

impl CommunicationType {
    pub fn as_number(self) -> u16 {
        self as u16
    }

    pub fn from_number(n: u16) -> Self {
        match n {
            0x0001 => CommunicationType::ping,
            0x0002 => CommunicationType::message_send,
            0x0003 => CommunicationType::update,
            _ => CommunicationType::ping,
        }
    }
}
