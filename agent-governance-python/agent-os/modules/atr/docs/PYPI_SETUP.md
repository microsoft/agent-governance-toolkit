# PyPI Publishing Setup Guide

This guide explains how to configure **Trusted Publishing** (OIDC) for automatic PyPI releases.

## Prerequisites

1. A PyPI account at [pypi.org](https://pypi.org)
2. Repository owner/admin access on GitHub

## Step 1: Reserve the Package Name on PyPI (First Time Only)

If this is a new package, do an initial publish manually:

```bash
# Build the package
python -m build

# Upload to TestPyPI first (recommended)
python -m twine upload --repository testpypi dist/*

# Then upload to PyPI
python -m twine upload dist/*
```

## Step 2: Configure Trusted Publishing on PyPI

1. Go to [pypi.org](https://pypi.org) and log in
2. Navigate to your project: **Your projects** → **agent-tool-registry**
3. Go to **Settings** → **Publishing**
4. Under "Add a new pending publisher" or "Add a new trusted publisher":

   | Field | Value |
   |-------|-------|
   | **Owner** | `microsoft` |
   | **Repository name** | `atr` |
   | **Workflow name** | `publish.yml` |
   | **Environment name** | `pypi` |

5. Click **Add**

## Step 3: Configure TestPyPI (Optional but Recommended)

Repeat the same steps on [test.pypi.org](https://test.pypi.org):

| Field | Value |
|-------|-------|
| **Owner** | `microsoft` |
| **Repository name** | `atr` |
| **Workflow name** | `publish.yml` |
| **Environment name** | `testpypi` |

## Step 4: Create GitHub Environments

1. Go to your GitHub repository: `github.com/microsoft/agent-governance-toolkit`
2. Navigate to **Settings** → **Environments**
3. Create two environments:

### Environment: `pypi`
- Click **New environment**
- Name: `pypi`
- Add protection rules (recommended):
  - ✅ Required reviewers (optional, for manual approval)
  - ✅ Deployment branches: `main` only

### Environment: `testpypi`
- Click **New environment**
- Name: `testpypi`
- No protection rules needed (for testing)

## Step 5: Create a Release

1. Go to **Releases** → **Create a new release**
2. Create a new tag: `v0.1.0`
3. Set the release title: `v0.1.0 - Initial Release`
4. Write release notes
5. Click **Publish release**

The GitHub Action will automatically:
1. Run tests
2. Build the package
3. Publish to PyPI using OIDC (no tokens needed!)

## Troubleshooting

### "Trusted publisher not found"
- Verify the workflow filename matches exactly (`publish.yml`)
- Verify the environment name matches exactly (`pypi`)
- Check that the GitHub repository owner/name match

### "Permission denied"
- Ensure `id-token: write` permission is set in the workflow
- Verify the environment is created in GitHub

## Manual Publishing (Fallback)

If OIDC fails, you can use API tokens:

1. Create an API token on PyPI (Account Settings → API tokens)
2. Add it as a GitHub secret: `PYPI_API_TOKEN`
3. Modify the workflow to use the token:

```yaml
- name: Publish to PyPI
  uses: pypa/gh-action-pypi-publish@release/v1
  with:
    password: ${{ secrets.PYPI_API_TOKEN }}
```

## References

- [PyPI Trusted Publishers](https://docs.pypi.org/trusted-publishers/)
- [GitHub OIDC](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/about-security-hardening-with-openid-connect)
- [pypa/gh-action-pypi-publish](https://github.com/pypa/gh-action-pypi-publish)
