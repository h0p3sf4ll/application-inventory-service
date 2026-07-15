# SBOM Summary

The machine-readable SBOM is provided as [SBOM.cdx.json](SBOM.cdx.json) in CycloneDX 1.5 JSON format.

## Package

| Field | Value |
| --- | --- |
| Name | `application-inventory-service` |
| Version | `1.6.15` |
| License | MIT |
| Runtime | Python `>=3.10` |

## Direct Runtime Dependencies

| Package | Constraint | Installed version used for this SBOM |
| --- | --- | --- |
| `cryptography` | `>=49.0.0` | `49.0.0` |
| `defusedxml` | `>=0.7.1` | `0.7.1` |
| `openpyxl` | `>=3.1.5` | `3.1.5` |
| `psycopg[binary]` | `>=3.3.4` | `3.3.4` |
| `PyJWT` | `>=2.10.1` | `2.13.0` |
| `requests` | `>=2.34.2` | `2.34.2` |

## Notes

- The SBOM reflects the Python runtime package and its installed dependency set in the local release environment.
- Container base image packages are not included in this application SBOM.
- Generate a container-level SBOM separately from the final image with tools such as Syft or Trivy in the deployment pipeline.

Example:

```bash
syft application-inventory-service:1.6.15 -o cyclonedx-json > container-sbom.cdx.json
```
