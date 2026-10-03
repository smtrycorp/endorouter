# Security

EndoRouter's job is to keep private work off cloud models, so a way to make it send something it should not is the
most important kind of bug. We want to hear about it.

## Reporting

Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"), or email
hello@smtry.ai with "EndoRouter security" in the subject. Please do not open a public issue for a leak path.

A useful report says what was sent, what label and sources it carried, which mode the router ran in, and where it
went. A leakbench case that reproduces it is ideal; we add every confirmed one to the suite.

We will acknowledge a report within three working days and tell you what we plan to do. Fixes ship as a new release
with the case credited to you, unless you prefer not to be named.

## In scope

- A private or unlabelled request reaching a cloud target in strict mode.
- A request labelled private, or carrying a private source, reaching a cloud target in any mode.
- A secret matching one of the documented detector rules, sent to the cloud under a public label.
- Anything sent before an audit record naming its destination was written, a send reported as anything other than sent, or prompt content written to the log.
- A caller that is not in `trusted_clients` getting work labelled public.
- A discovered local target that forwards to a remote model without the router noticing.

## Known limits, not vulnerabilities

These are documented in the README: secrets split across messages in ways the detectors do not rejoin, encrypted or
compressed data, base64 wrapped across lines, confidential prose under a public label, and a target you declared
local yourself that is not.

## Supported versions

Before 1.0, fixes go into the next release; there are no backports.
