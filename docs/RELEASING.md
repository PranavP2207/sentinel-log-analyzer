# Releasing Sentinel

Releases are published to GitHub with a wheel, source distribution, and SHA-256 checksums. The workflow does not publish to PyPI.

## Prepare a version

1. Set the same version in `pyproject.toml` and `sentinel/__init__.py`.
2. Move the relevant `CHANGELOG.md` entries into a dated version section.
3. Add `docs/releases/vVERSION.md` with changes, installation instructions, validation, and known limits.
4. Run `python -m unittest discover -s tests -v` and try the installed CLI. Record skipped tests and platform limits.
5. Commit and push to `main`. Wait for all Ubuntu/Windows CI jobs to pass.

## Publish

Create an annotated version tag on the tested commit and push it:

```sh
git tag -a v0.1.0 -m "Sentinel v0.1.0"
git push origin v0.1.0
```

Use the intended version in both commands for future releases. Pushing a `v` tag starts `.github/workflows/release.yml`, which:

- Verifies that the tag, project metadata, and Python package versions agree.
- Runs the test suite on Ubuntu.
- Builds a wheel and source distribution with `python -m build`.
- Installs the wheel and checks the installed command using the demo fixture.
- Generates `SHA256SUMS` for the wheel and source archive.
- Creates the GitHub release using the matching version's release notes and uploads the assets.

The workflow uses the repository's `GITHUB_TOKEN` with `contents: write` permission for its release job. It needs no personal token or package-index credential. Check the Actions result and release assets after publication.

If a failure occurs before the release is created, fix the cause before retrying. Do not move or overwrite an already published version tag. For a correction to a published package, prepare a new version and document the change.
