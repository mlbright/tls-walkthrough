# TLS 1.3 Walkthrough

An educational tool that takes one real TLS 1.3 handshake apart, message by message, and re-does the client's security checks by hand so a learner can see each one happen.

## Language

**Learner**:
The person running the walkthrough: a developer who uses HTTPS daily but has never looked inside a handshake.
_Avoid_: User, client (the client is the TLS client)

**Walkthrough**:
One run of the tool against one server, from prerequisites to summary.
_Avoid_: Session (that word belongs to TLS itself)

**Section**:
A numbered top-level topic of the walkthrough, such as "ClientHello" or "Certificate".

**Step**:
The smallest unit of the walkthrough: the output under one heading, either a section or a subsection within it. The walkthrough pauses after every step.
_Avoid_: Phase, stage

**Check**:
One security test a TLS client performs, re-done by hand, ending in a verdict: PASS, FAIL, WARN (most clients accept it, with caveats) or SKIP (the check could not run). Unlike a real client, the walkthrough continues past a FAIL.
_Avoid_: Test, assertion

**Intro**:
The explanation at the start of a step that tells the learner what to look for.

**Recap**:
The short explanation shown at the pause after a step that points back at the output just seen and says why it matters.
_Avoid_: Summary (that is the final section)
