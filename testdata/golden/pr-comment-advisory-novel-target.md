No change in open findings · 6 open · 8 mitigated · 1 unverified

Advisory (AI)

AI-generated — does not affect the merge gate.

**tampering** · `uploads bucket`
Object lock is off on uploads bucket while a process holds write credentials into it.
Suggestion: Enable object lock, or remove write credentials from non-audit principals.
