/// HTTP/2 protocol errors.
pub const Http2Error = error{
    /// Invalid frame format or content.
    InvalidFrame,
    /// Frame size exceeds maximum allowed.
    FrameTooLarge,
    /// Connection protocol error.
    ProtocolError,
    /// Stream state error.
    StreamError,
    /// Flow control error.
    FlowControlError,
    /// Settings timeout.
    SettingsTimeout,
    /// Connection closed.
    ConnectionClosed,
    /// Insufficient buffer space.
    InsufficientBuffer,
    /// Invalid stream state.
    InvalidStreamState,
    /// Compression error.
    CompressionError,
};
