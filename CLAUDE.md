# cert2jks - CLAUDE.md

## Project Overview

Go module/application repository scaffolded from `cert2jks`.

## Current Status
- **Last Updated**: TBD
- **Current Phase**: Development
- **Health**: Green

## Active Tasks
None.

## Recent Progress
- Initial scaffold from `cert2jks`

## Blockers & Issues
None currently.

## Architecture & Key Decisions
- **Language**: Go 1.23+
- **Lint**: `golangci-lint` (config in `.golangci.yml`)
- **Pre-commit**: `gofmt`, `go vet`, `go mod tidy`, `golangci-lint`
- **Build**: standard `go build`, orchestrated via `Makefile`

## Useful Commands

```bash
make help          # Show all targets
make build         # Compile
make test          # Run unit tests
make test-race     # Run with race detector
make cover         # Coverage report
make lint          # golangci-lint
make fmt           # gofmt -s -w .
make vet           # go vet
make tidy          # go mod tidy
```

## Required Claude Code plugins

Agents and slash commands live in the AxonOps shared marketplace at
`bitbucket.org/axonops/claude-skills`. Install once per developer:

```bash
git clone git@bitbucket.org:axonops/claude-skills.git ~/axonops-claude-skills
~/axonops-claude-skills/install.sh --plugin engineering-agents --plugin go-bootstrap
```

Plugins used:
- `engineering-agents` — `secrets-auditor`, `docs-quality-reviewer`, `code-reviewer`, `go-quality`, `go-bug-fixer`, `test-writer`, `kube`, `tech-decision-maker`
- `go-bootstrap` — `go-specialist`, `issue-writer` (Go-specific), `/create-pr`, `/create-jira-ticket`, `/create-github-issue`

## Workflow — Agent Gates

These agents are mandatory gates, not optional tools.

### Before any commit:
- **secrets-auditor** — verify no plaintext credentials, API keys, or tokens

### Before opening a PR:
- **go-quality** — idiomatic Go, lint compliance, anti-patterns
- **docs-quality-reviewer** — README quality and branding compliance
- **code-reviewer** — bugs, regressions, missing tests
- **security-reviewer** — input validation, OWASP, dependency review
- **test-writer** — coverage gaps, missing edge cases

### Before creating a Jira issue:
- **issue-writer** — full requirements, acceptance criteria, testing notes
- Then **atlassian:triage-issue** for duplicate detection

## Code Standards

- All exported identifiers must have doc comments starting with the identifier name
- Errors wrapped with `fmt.Errorf("...: %w", err)` — never lose error chain
- Context-aware functions accept `ctx context.Context` as first arg
- No `panic` in library code — return errors
- Tests live next to source (`foo_test.go`)
- Race detector must pass (`make test-race`)
- Coverage target: ≥ 80% for non-trivial packages

## Known Limitations & Tech Debt
- Document here as discovered

## Next Steps & Roadmap
- Define module structure
- Add CI matrix (multiple Go versions if needed)
