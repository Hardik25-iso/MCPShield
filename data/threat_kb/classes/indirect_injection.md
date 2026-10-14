# Indirect prompt injection

The attacker does not control the tool metadata but controls data the tool returns: an invoice note, a web
page, a file, a calendar entry. The injected instruction rides inside otherwise-legitimate tool output and is
executed when the agent reads it. Defence: treat all tool output as untrusted, scan it for instructions, and
taint-track any value derived from it before it reaches a privileged tool.
