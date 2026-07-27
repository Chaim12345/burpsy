//! burpsy-tools — the supporting tools: Decoder, Comparer, Logger, Organizer, match-and-replace.
//!
//! These are pure transformations over bytes and stored messages, deliberately free of any I/O so
//! they can be exercised directly in tests and reused by the proxy, the UI and the MCP server alike.
