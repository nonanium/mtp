// Communication types used in the MTP protocol.
// The numeric values are part of the on‑wire format.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(non_camel_case_types)]
pub enum CommunicationType {
    ping = 0x01,
    message_send = 0x02,
    update = 0x03,
}

impl CommunicationType {
    pub fn as_number(self) -> u8 {
        self as u8
    }

    pub fn from_number(n: u8) -> Self {
        match n {
            0x01 => CommunicationType::ping,
            0x02 => CommunicationType::message_send,
            0x03 => CommunicationType::update,
            _ => CommunicationType::ping,
        }
    }
}
