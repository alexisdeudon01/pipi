# Repository Guidelines

## Project Structure & Module Organization
- Root files: `README.md`/`README_PRO.md`, `config.json`, and `scripts/` (bootstrap, GUI runner, Docker install, agent deploy).
- `app/` holds the Ubuntu GUI (`gui.py`) and the Pi agent package (`app/pi_agent/`).
- `docker/` stores the Pi agent Dockerfile referenced by `scripts/deploy_pi_agent.sh`.
- No separate assets area yet; place new helpers beside the component they touch.

## Build, Test, and Development Commands
- `pip install -r requirements.txt` installs Python/Tk dependencies for both the GUI and helpers.
- `./scripts/bootstrap_ubuntu.sh` prepares the workstation virtualenv and prerequisites.
- `./scripts/run_gui.sh` activates the venv and starts the GUI to confirm SSH+SSE flow.
- `docker-compose up --build` exercises the container described in `README.md` for quick Docker smoke tests.
- `./scripts/install_docker_pi.sh` installs Docker on a fresh Pi before deployment.
- `./scripts/deploy_pi_agent.sh` builds the agent from `docker/PI/Dockerfile`, pushes it via SSH, and launches the SSE server on port 8787.

## Coding Style & Naming Conventions
- Follow Python standards: 4 spaces, snake_case names, PascalCase for classes, and keep GUI helpers in `gui.py` while moving reusable logic into `app/pi_agent/` modules.
- Document new `config.json` keys in the README and keep them lowercase_snake_case (e.g., `pi_host`, `agent_port`).
- No automated formatter is enforced yet; rely on manual linting (PEP 8) before commits.

## Testing Guidelines
- No automated suite exists; verify changes by running `./scripts/run_gui.sh` and watching agent logs via `docker logs -f pi-agent` or the SSE stream.
- If you add tests, create a `tests/` folder and name files `test_<feature>.py` to mirror the new functionality.
- Note any manual steps (scripts, config tweaks, screenshots) in PR descriptions so reviewers can reproduce verification.

## Commit & Pull Request Guidelines
- History uses terse commits (e.g., `rere`, `kjlj`, `sd`); prefer clear imperative summaries such as `Document SSE health endpoint`.
- PRs should summarize the change, list relevant commands (bootstrap/run/deploy), mention config updates, and confirm whether the GUI and agent were exercised.
- Provide context for UI, deployment, or config changes (linked issues, screenshots, logs) to help reviewers evaluate the impact.

## Security & Configuration Tips
- Treat `config.json` as a template; never commit real credentials and document overrides in PRs.
- When you adjust SSH details or ports, reflect the change in both `config.json` and the scripts that depend on those values to keep deployments aligned.
