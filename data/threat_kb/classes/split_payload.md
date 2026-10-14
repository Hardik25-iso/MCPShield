# Split payload

The malicious instruction is fragmented across several tool descriptions (or several outputs) so that no
single piece looks dangerous, but the concatenation forms a working instruction. Defence: scan the
concatenation of all of a server's descriptions, and re-query the threat KB with combined fragments.
