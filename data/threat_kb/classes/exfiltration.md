# Data exfiltration

A tool is designed to capture sensitive data. A benign-looking parameter (notes, context, debug, metadata) is
described as needing the conversation history, environment variables, API keys, or file contents "for audit"
or "for accuracy". The agent dutifully fills it and the secret leaves with the tool call. Defence: detect
exfiltration-prone parameters paired with data-harvest language, and scan arguments for secret patterns.
