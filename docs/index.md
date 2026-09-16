# Documentation map

[Back to the README](../README.md)

Start with the public I/O model, then follow the component whose behavior you need to understand.

![Public inputs, Wrapper processing, and caller-owned outcome handling.](diagrams/overview.svg)

## Reading paths

- **First integration:** [quick start](quick-start.md) → [configuration](configuration.md) → [outcomes](outcomes.md).
- **Login and identity:** [authentication](authentication.md) → [MFA](multi-factor-authentication.md) → [persistence](persistence.md).
- **Resource access:** [authorization](authorization.md), including public pages and guest roles.
- **Request protection:** [CSRF](csrf.md) and [throttling](throttling.md).
- **Internal behavior:** [request workflow](workflow.md) and [authentication lifecycle](multi-factor-authentication.md#authentication-lifecycle).

## Diagram conventions

Diagrams answer different questions rather than combining configuration, classes, request decisions, and stored state in one graph:

| Diagram | Question |
| --- | --- |
| [Overview](diagrams/overview.svg) | What does the application supply and receive? |
| [Configuration tree](diagrams/configuration-tree.svg) | Which XML tags contain which other tags? |
| [Request flow](diagrams/request-flow.svg) | Which stage runs next, and when do later stages stop? |
| [Authentication lifecycle](diagrams/authentication-lifecycle.svg) | Which identity state survives between requests? |
| [Form login](diagrams/form-login.svg) | How does a login form become a verified identity? |
| [OAuth2](diagrams/oauth2.svg) | How does a provider callback become a local identity? |
| [Authorization](diagrams/authorization.svg) | How are guest and authenticated requests evaluated? |
| [Persistence](diagrams/persistence.svg) | How is identity restored, saved, and delivered? |
| [CSRF](diagrams/csrf.svg) | Which identity context is a submitted token validated against? |
| [Throttling](diagrams/throttling.svg) | When are checks and penalties applied? |

Numbered circles refer to explanations immediately below the image on its guide page. They are not inherently chronological. Arrows indicate flow except in the configuration tree, where lines indicate containment. Dashed shapes or arrows indicate optional or conditional participation; the accompanying text gives the condition.

The new diagrams use native SVG text and shapes, without embedded raster labels, and include accessible titles and descriptions. Edit their SVG source to change wording or layout. The original draw.io-exported [main.svg](main.svg) and [xml.svg](xml.svg) are preserved as your working originals; the guides use the new diagrams in `diagrams/`.

## Source and examples

The main public entry points are [Wrapper](../src/Wrapper.php) and [Request](../src/Request.php). Configuration objects detect and validate implementation class names; deeper security code constructs the XML-selected DAOs. OAuth2 services/state and route-role detection are explicitly supplied integrations.

The [example XML](examples/security.xml) is an application template, not a production-ready configuration. Its `App\Security\...` classes must be supplied by the application, and its secret must be replaced.
