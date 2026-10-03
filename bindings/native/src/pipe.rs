//! Native pipe aliases using the shared lifecycle and stream implementation.

pub type PipeWriter<S = crate::NativeSendStream> = mtp_core::PipeWriter<S>;
pub type PipeReader<R = crate::NativeRecvStream> = mtp_core::PipeReader<R>;
