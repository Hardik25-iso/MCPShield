# Tool poisoning

A malicious MCP server embeds instructions for the agent inside a tool's description. Because agents treat
tool metadata as trusted context, the hidden text is followed as if it came from the developer. Payloads are
often concealed with `<IMPORTANT>` tags, zero-width characters, homoglyphs, base64 blobs, or HTML comments so
a human skimming the manifest does not notice them. Defence: scan every description (after de-obfuscation)
for imperative instructions and hidden text, and pin a hash of the approved description.
