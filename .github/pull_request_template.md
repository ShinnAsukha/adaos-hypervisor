<!-- Thank you for contributing to OXware! Please fill in the relevant
sections below and delete the rest. Empty PRs and "I'll fix it later"
descriptions are routinely closed without review. -->

## Summary

<!-- 1–2 sentences. What does this PR do? -->

## Type of change

- [ ] 🐛 Bug fix (non-breaking change that fixes an issue)
- [ ] ✨ New feature (non-breaking change that adds functionality)
- [ ] 💥 Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] 🔒 Security fix (assign a SEC-NNN id; reference [`SECURITY.md`](../SECURITY.md))
- [ ] 📝 Documentation only
- [ ] 🌍 Translation / i18n
- [ ] ⚡ Performance
- [ ] 🧹 Refactor / cleanup

## Linked issue

Closes #
<!-- Or: References #123, partially implements #456 -->

## Checklist

- [ ] My code follows the style of this project (`make security` and `make test` pass locally)
- [ ] I have added an entry in `CHANGELOG.md` under the next unreleased version
- [ ] I have updated relevant docs (`README.md`, `oxware.top/docs/`)
- [ ] **i18n parity:** if I touched `oxware/frontend/templates/index.html`, I ran `make i18n` (or the pre-commit hook ran it for me)
- [ ] **Modularization:** new routes land in `oxware/backend/blueprints/`, not in `app.py` (see [`MODULARIZATION_PLAN.md`](../MODULARIZATION_PLAN.md))
- [ ] **Security:** if this PR touches auth, federation, runbook executor, plugin SDK, or any subprocess call, I have considered SSRF / path traversal / argv injection and used `security_utils.*` helpers where appropriate
- [ ] For security fixes: I have requested a SEC-NNN id and added the entry to `SECURITY.md`
- [ ] Tests added or updated; SEC-017..033 regression suite stays green

## How to verify

<!-- Step-by-step instructions so a reviewer can reproduce your test. -->

## Screenshots / output

<!-- Drop screenshots, terminal output, or curl examples here if relevant. -->

---

By submitting this PR, you agree to license your contribution under the [MIT License](../LICENSE).
