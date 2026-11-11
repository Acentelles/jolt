/// A streaming visitor: false stops before reading another shape member.
pub trait KeySink {
    fn word(&mut self, value: u64) -> bool;
}
