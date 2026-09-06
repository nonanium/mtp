use crate::CommunicationError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirstFrameDisposition {
    Message,
    Pipe(u32),
}

pub fn classify_first_frame(
    is_pipe_request: bool,
    pipe_id: Option<u32>,
    pipe_is_expected: bool,
) -> Result<FirstFrameDisposition, CommunicationError> {
    if !is_pipe_request {
        return Ok(FirstFrameDisposition::Message);
    }
    let pipe_id = pipe_id.filter(|id| *id != 0).ok_or_else(|| {
        CommunicationError::Other("PipeRequest frame must contain a non-zero id".into())
    })?;
    if pipe_is_expected {
        Ok(FirstFrameDisposition::Pipe(pipe_id))
    } else {
        Ok(FirstFrameDisposition::Message)
    }
}
