//! TLS integration has moved out of the core package.
//!
//! Use an adapter package such as `http2-boring` to terminate TLS with
//! BoringSSL, verify ALPN `h2`, and call `http2.serveConnection` or
//! `http2.transport.serveConnection` with the decrypted application-data
//! reader and writer.

