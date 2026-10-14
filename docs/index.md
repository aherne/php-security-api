# Documentation map

[Back to the README](../README.md)

Start with the state machine's public boundary, then follow the part of the contract you need:

1. [Basic I/O and Wrapper integration](io.md) — construct `Request`, inject optional integrations, run `Wrapper`, and dispatch its outcome.
2. [XML configuration](configuration.md) — supported hierarchy, attributes, defaults, class selection, persistence, authentication, authorization, and MFA.
3. [Packets and statuses](packets.md) — numbered diagram reference, public/internal outcomes, failure reasons, callbacks, and bearer-token delivery.
4. [Exceptions](exceptions.md) — framework exception types that can escape the state machine.

## Component guides

- [Authentication](authentication.md)
- [Multi-factor authentication](multi-factor-authentication.md)
- [Authorization](authorization.md)
- [Persistence](persistence.md)
- [CSRF](csrf.md)
- [Throttling](throttling.md)
- [Internal request workflow](workflow.md)

The [example XML](examples/security.xml) is a development template. Its `App\Security\...` classes must be implemented by the host application, and its placeholder secrets must be replaced before deployment.
