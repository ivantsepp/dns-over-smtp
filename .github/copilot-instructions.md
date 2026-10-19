<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# DNS over SMTP Project Instructions

This is a Go project that implements DNS queries and responses tunneled through the SMTP protocol.

## Project Architecture

- `main.go`: Entry point with CLI interface supporting both client and server modes
- `internal/client/`: DNS client that forwards queries via SMTP
- `internal/server/`: DNS server that processes queries received via email

## Key Design Patterns

- Use the `github.com/miekg/dns` library for DNS message parsing and construction
- Encode/decode DNS messages as base64 for email transmission
- Follow Go best practices with proper error handling and logging
- Use structured configuration with dedicated Config structs

## Development Guidelines

- Maintain separation between client and server functionality
- Implement proper SMTP authentication and error handling
- Use descriptive logging for debugging email-based DNS operations
- Consider email delivery latency in timeout configurations
- Validate DNS message encoding/decoding operations

## Testing Considerations

- Mock SMTP operations for unit tests
- Test DNS message encoding/decoding separately
- Consider integration tests with actual email servers
- Test both UDP and TCP DNS query handling
