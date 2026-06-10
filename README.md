# SecureCode AI

SecureCode AI is a full-stack Next.js code security reviewer combining deterministic static rules with Google Gemini.

## Checks

- Hardcoded secrets
- SQL and command injection
- Dynamic code execution
- Cross-site scripting patterns
- Missing server-side validation
- Weak cryptography
- Path traversal
- Broad CORS configuration
- Insecure HTTP endpoints
- Sensitive logging
- Contextual issues identified by Gemini

## Security design

- Gemini API key is server-only
- Code-size validation and request rate limiting
- Static analysis works when Gemini is unavailable
- Structured JSON model output
- Review prompt treats submitted code as untrusted data
- Evidence is redacted before display

Do not submit private source code, production credentials, customer data, or proprietary secrets.

Gemini integration follows the official [Gemini API documentation](https://ai.google.dev/gemini-api/docs).
