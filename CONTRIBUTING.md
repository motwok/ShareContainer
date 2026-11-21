# Contributing to ShareContainer

Thanks for your interest in ShareContainer!

This project follows a [Code of Conduct](CODE_OF_CONDUCT.md); please be respectful.

> **Security issue?** Do **not** open a public issue; report it privately, see [SECURITY.md](SECURITY.md).

## Ways to contribute

- **Bug reports**: [open an issue](https://github.com/motwok/ShareContainer/issues)
- **Feature requests**: [open an issue](https://github.com/motwok/ShareContainer/issues)
- **Pull requests** are welcome, see below.

Ideas, reproductions and well-described problems are genuinely valuable too.

## Pull requests

ShareContainer runs a file server on the host network and holds user passwords, so every change is
reviewed carefully before it is merged. To make that easy:

- For anything larger than a small fix, open an issue first so the approach can be agreed on.
- Keep a pull request focused on one change. Work on a branch of your fork and target `master`.
- Use a Conventional Commit style title, for example `feat: ...`, `fix: ...`, `docs: ...`.
- Write code, comments and documentation in English. New packages in the image need to be agreed in an
  issue first.
- Do not put raw non-ASCII characters into source code; write them as escape sequences (`\uXXXX`).
- Diagrams in Markdown are Mermaid, not ASCII art.
- The build, including the smoke test, must be green. Test coverage of `src/` is 100 % (branches
  included) and stays there: add tests with every change.

Run the tests locally:

```sh
pip install pytest coverage pyyaml bcrypt
python -m coverage run --branch --source=src/sharecontainer -m pytest tests/unit
python -m coverage report -m --fail-under=100
docker build -t sharecontainer:test . && IMAGE=sharecontainer:test sh tests/smoke/run.sh
```

By submitting a pull request you agree that your contribution is licensed under the
**GNU AGPL v3** (see [LICENSE](LICENSE)).

## Writing a good bug report

Please include:

- **What happened** and **what you expected**.
- The **ShareContainer version**: the image tag or digest.
- The **host platform**: distribution, architecture, kernel (`uname -r`) and **Docker version**.
- The **client**: operating system and version, and whether it uses a NIC team.
- The relevant parts of your **configuration** and of the **container log** (`docker logs <container>`).
- For Multichannel problems on Windows, the output of `Get-SmbMultichannelConnection` during a copy.
- **Steps to reproduce**, if you can; even rough ones help.

Remove host names, addresses, user names or share names you do not want to make public before posting.

## Feature requests

Describe the problem you're trying to solve, not just a proposed solution; it helps find the best fit.
Note that not every request will be implemented; ShareContainer intentionally stays small and focused.

## Forking

ShareContainer is licensed under the **GNU AGPL v3** (see [LICENSE](LICENSE)). You are of course free to
fork and modify it under those terms.

## Support Me

If ShareContainer helps you, you can support it: [Buy Me a Coffee](https://ko-fi.com/motwok)
