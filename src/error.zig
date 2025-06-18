/// HTTP/2 error codes as defined in RFC 7540.
pub const ErrorCode = enum(u32) {
    NO_ERROR = 0x0,
    PROTOCOL_ERROR = 0x1,
    INTERNAL_ERROR = 0x2,
    FLOW_CONTROL_ERROR = 0x3,
    SETTINGS_TIMEOUT = 0x4,
    STREAM_CLOSED = 0x5,
    FRAME_SIZE_ERROR = 0x6,
    REFUSED_STREAM = 0x7,
    CANCEL = 0x8,
    COMPRESSION_ERROR = 0x9,
    CONNECT_ERROR = 0xa,
    ENHANCE_YOUR_CALM = 0xb,
    INADEQUATE_SECURITY = 0xc,
    HTTP_1_1_REQUIRED = 0xd,
};

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
