# Security Policy

## Reporting a vulnerability

Report security problems privately, never in a public issue.

- **GitHub:** open a private report from the repository's Security tab: [Report a vulnerability](https://github.com/ninja-c9/mintrun/security/advisories/new).
- **Email:** `<security-contact-email>` (placeholder: the maintainer fills in the address).

If neither works for you, open a public issue that asks for a private contact and leaves out every detail of the problem.

Include:

- the output of `mintrun -version`, and your OS and its version;
- the steps or a small script that shows the problem, and what you expected instead;
- which promise in the [threat model](docs/threat-model.md) it breaks, if you know.

Never send a real credential. Use throwaway values, and remove tokens, user names, host names, and local paths from any log you attach, `~/.mintrun/audit.jsonl` included.

## Supported versions

Only the latest release tag gets security fixes. A fix lands on `main` first and ships in the next tag; older tags get no backports.

## What counts as a vulnerability

The [threat model](docs/threat-model.md) lists what `mintrun` promises, the tests behind each promise, and the known limits of each. A way around a documented control is a vulnerability. Some examples:

- a secret that reaches an agent, the terminal, or `audit.jsonl` in a form the scrubber covers;
- a request that runs although `policy.json`, the pause file, or a denied approval should stop it;
- a sandboxed command that reads `~/.mintrun` or the keystore folder by its path;
- an approval that counts without an answer from you.

A limit the threat model already lists is not a vulnerability. For example, the command runs as your user and can read your keystore unless the sandbox is on. A report that a limit is wider than the threat model says is welcome.
