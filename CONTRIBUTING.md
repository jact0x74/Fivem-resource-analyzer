# Contributing

Thanks for your interest! Issues, test fixtures and pull requests are welcome.

1. Open an issue describing the bug or proposed feature, ideally with a minimized `fxmanifest.lua` example that contains no secrets or private scripts.
2. Fork the repo and create a descriptive branch.
3. Run `python -m unittest discover -s tests -v` locally.
4. Include a test for parsing or analysis behavior changes. Update the README if behavior changes.
5. Submit a pull request describing the expected behavior and its FiveM documentation reference where possible.

## Scope

This project focuses on **read-only** manifest analysis. It does not evaluate Lua or execute server scripts. Avoid sending real authentication tokens, session keys or paid/escrow-protected code in issues or PRs.

## Code of Conduct

Be respectful and professional. We welcome feedback, technical disagreement and contributions from people at all skill levels. Harassment and discriminatory behavior are not welcome.
