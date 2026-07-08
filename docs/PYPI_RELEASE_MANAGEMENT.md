# PyPI Release Management

Application Inventory Service publishes to PyPI from the GitHub `Publish` workflow.

## Current Release Policy

- Publish only from GitHub Releases.
- Keep the GitHub Actions environment named `pypi`.
- Prefer PyPI Trusted Publishing over long-lived API tokens when the project owner can configure it.
- If an API token is used, scope it to `application-inventory-service`, store it only as a GitHub environment secret, and rotate it after exposure in chat, logs, screenshots, or issue trackers.

## Old Releases

PyPI supports yanking as the safer alternative to deletion. A yanked release is ignored by normal resolver behavior but remains available for exact pins, which avoids breaking downstream builds that intentionally pinned a version.

Use yanking when an older release is broken, vulnerable, or should not be selected by default.

Use deletion only when a PyPI project owner intentionally accepts the blast radius. PyPI deletion is permanent and irreversible; deleted files cannot be restored or re-uploaded.

## Recommended Action for This Project

Keep only the current version active. Yank earlier versions from the PyPI project management UI unless there is a strict legal or security requirement to delete them.

Manual owner workflow:

1. Sign in to PyPI as a project owner.
2. Open `application-inventory-service`.
3. Open **Releases**.
4. For every version older than the current release, choose **Yank** or **Delete**.
5. Use the reason `Superseded by current hardened release`.
6. Confirm that the PyPI project page shows only the current version as active.

The upload API token used by CI is not sufficient for this owner-only project management action.
