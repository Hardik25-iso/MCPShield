# Rug pull

A tool is benign when first reviewed and approved, then its description or schema silently changes to a
malicious version after it has earned trust. Defence: pin a SHA-256 of the canonical tool definition at first
approval and quarantine the tool on any later change until a human re-approves it, showing a diff.
