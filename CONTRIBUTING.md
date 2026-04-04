# Contributing to Honeypot Threat Intelligence Platform

Thank you for your interest in contributing! This is an active security research project, and contributions that improve the quality of data collection, analysis, threat intelligence output, or documentation are warmly welcomed.

Please read this guide fully before opening a pull request or issue.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Branching Strategy](#branching-strategy)
- [Commit Message Convention](#commit-message-convention)
- [Pull Request Process](#pull-request-process)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Features](#suggesting-features)
- [Security Disclosures](#security-disclosures)
- [Style Guidelines](#style-guidelines)

---

## 🤝 Code of Conduct

This project follows a simple rule: **be professional, be respectful, be constructive.**

- Treat all contributors with respect regardless of experience level
- Focus feedback on the work, not the person
- No harassment, discrimination, or abusive language will be tolerated
- Security research discussions must remain within ethical and legal boundaries

Violations may result in contributions being rejected or contributors being blocked.

---

## 💡 How Can I Contribute?

### 🐛 Bug Reports
Found something broken? Open an issue using the **Bug Report** template. Include:
- What you expected to happen
- What actually happened
- Steps to reproduce
- Your environment (OS, Python version, Docker version)

### ✨ Feature Requests
Have an idea for improvement? Open an issue using the **Feature Request** template.

### 🔧 Code Contributions
Areas where contributions are most valuable:

| Area | Examples |
|---|---|
| **New honeypot services** | Add ConPot (ICS/SCADA), Mailoney (SMTP), Snare (HTTP advanced) |
| **Analysis scripts** | Improve TTP extraction accuracy, add ML clustering models |
| **STIX feed quality** | Richer relationship objects, additional STIX object types |
| **Geo-visualization** | Animated attack timelines, D3.js interactive maps |
| **Documentation** | Improve setup guides, add translated READMEs, diagram improvements |
| **CI/CD** | GitHub Actions for automated linting, testing, STIX validation |

### 📄 Documentation
Improve the README, add inline code comments, create wiki pages, or write blog-style writeups of findings.

---

## 🛠️ Development Setup

### 1. Fork and Clone

```bash
# Fork via GitHub UI, then:
git clone https://github.com/<YOUR-USERNAME>/honeypot-threat-intelligence.git
cd honeypot-threat-intelligence
```

### 2. Create a Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate       # Linux / macOS
.\venv\Scripts\activate        # Windows

pip install -r analysis/requirements.txt
```

### 3. Add the Upstream Remote

```bash
git remote add upstream https://github.com/ChandraVerse/honeypot-threat-intelligence.git
git fetch upstream
```

### 4. Sync Before You Start

Always sync with upstream before starting new work:

```bash
git checkout main
git pull upstream main
```

---

## 🌿 Branching Strategy

Use descriptive branch names with a prefix that matches the type of change:

| Prefix | Use for |
|---|---|
| `feat/` | New features or capabilities |
| `fix/` | Bug fixes |
| `docs/` | Documentation updates only |
| `refactor/` | Code restructuring without behavior change |
| `test/` | Adding or improving tests |
| `ci/` | GitHub Actions / workflow changes |

**Examples:**
```
feat/add-conpot-integration
fix/stix-generator-timestamp-bug
docs/improve-elk-setup-guide
refactor/ioc-aggregator-dedup-logic
```

---

## 📝 Commit Message Convention

This project uses **Conventional Commits** format:

```
<type>(<scope>): <short summary>

[optional body]

[optional footer]
```

**Types:**
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation only
- `refactor` — code restructuring
- `test` — tests
- `ci` — CI/CD changes
- `chore` — maintenance tasks

**Examples:**
```
feat(analysis): add K-Means attacker behavior clustering
fix(stix): correct timestamp format in indicator objects
docs(readme): add Hetzner VPS setup instructions
refactor(enrichment): batch AbuseIPDB API calls to reduce rate limiting
```

**Rules:**
- Use the imperative mood: "add feature" not "added feature"
- Keep the summary under 72 characters
- Reference issue numbers in the footer: `Closes #42`

---

## 🚀 Pull Request Process

1. **Ensure your branch is up to date** with `upstream/main` before opening a PR
2. **Test your changes** — run the relevant scripts and verify outputs are correct
3. **Update documentation** — if your change affects usage, update the README or relevant docs
4. **STIX validation** — if modifying the TIP feed, validate output against the STIX 2.1 spec using `stix2-validator`:
   ```bash
   pip install stix2-validator
   stix2_validator tip-feed/stix-bundles/your_bundle.json
   ```
5. **Open the PR** against the `main` branch with:
   - A clear title following the commit convention
   - A description explaining **what** changed and **why**
   - Screenshots or sample output if applicable
   - Reference to any related issues (`Closes #N`)

6. **Review process**: PRs will be reviewed within 5–7 days. Address requested changes promptly. PRs inactive for 30 days will be closed.

---

## 🐛 Reporting Bugs

Open an issue with the label `bug`. Include:

```markdown
**Environment**
- OS: Ubuntu 22.04
- Python: 3.11.x
- Docker: 24.x
- T-Pot version: 23.x

**Description**
A clear and concise description of the bug.

**Steps to Reproduce**
1. Run `python ttp_extractor.py --days 30`
2. Observe error: ...

**Expected Behavior**
What you expected to happen.

**Actual Behavior**
What actually happened (include full error traceback).

**Logs / Screenshots**
Paste relevant log output here.
```

---

## 💡 Suggesting Features

Open an issue with the label `enhancement`. Include:

```markdown
**Problem Statement**
Describe the problem this feature would solve.

**Proposed Solution**
Describe your proposed approach.

**Alternatives Considered**
Any other approaches you considered and why you rejected them.

**Additional Context**
Links, references, related research, or mockups.
```

---

## 🔐 Security Disclosures

If you discover a **security vulnerability** in this project's code or infrastructure:

- **Do NOT open a public issue**
- Email directly: `chakrabortychandrasekhar185@gmail.com`
- Subject line: `[SECURITY] Honeypot-TI Vulnerability Disclosure`
- Include a description of the vulnerability, steps to reproduce, and potential impact
- You will receive a response within 72 hours

Responsible disclosure is appreciated. Credit will be given in the project changelog.

---

## 🎨 Style Guidelines

### Python
- Follow [PEP 8](https://pep8.org/) — enforced via `flake8`
- Max line length: **100 characters**
- Use type hints for all function signatures
- Docstrings required for all public functions (Google style):
  ```python
  def enrich_ip(ip: str, api_key: str) -> dict:
      """Enrich an IP address with AbuseIPDB reputation data.

      Args:
          ip: The IPv4 address to query.
          api_key: AbuseIPDB API key.

      Returns:
          A dict containing abuseConfidenceScore, countryCode, and isp.
      """
  ```
- No hardcoded credentials — always use `.env` and `os.getenv()`
- Run `flake8 analysis/` before committing

### Bash / Shell Scripts
- Include a header comment block explaining purpose and usage
- Use `set -euo pipefail` at the top of every script
- Quote all variables: `"${VAR}"` not `$VAR`

### JSON / STIX
- Validate all STIX bundles with `stix2-validator` before committing
- Pretty-print JSON with 2-space indentation
- Include `spec_version: "2.1"` in all STIX objects

### Documentation
- Use sentence case for headings
- Code blocks must specify the language (` ```bash `, ` ```python `, ` ```json `)
- Keep line length under 120 characters in Markdown files

---

## 🏅 Recognition

All contributors will be acknowledged in the project's `CONTRIBUTORS.md` file (added upon first merged PR) and in the acknowledgements section of the research paper.

---

<p align="center">
  Thank you for helping make this research better. 🛡️
  <br/>
  <a href="https://github.com/ChandraVerse/honeypot-threat-intelligence">Back to Repository</a>
</p>
