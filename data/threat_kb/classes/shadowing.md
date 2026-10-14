# Tool shadowing

A description on one (often untrusted) server tries to change how a different, privileged tool behaves, for
example by instructing the agent to bcc a hidden recipient whenever it sends email, or to redirect payments.
The malicious tool need never be called; its description alone rewrites the agent's behaviour for other tools.
Defence: flag any description that references tool names it does not own, especially privileged ones.
