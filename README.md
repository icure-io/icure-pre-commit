# iCure pre-commit

Installation scripts, sample configurations, custom detect-secrets plugins/filter and any other files related to pre-commit hooks we may want to share across multiple iCure projects.

## Installation scripts

Script to install various tools useful or necessary for pre-commit hooks.

- **install_required_tools.sh:** system-wide installation of all tools required by pre-commit hooks (currently only `pre-commit` itself). This script will NOT set up the pre-commit hooks: after the installation is successful you must manually run `pre-commit install`.
- **install_optional_detect-secrets.sh:** system-wide installation of `detect-secrets`, only necessary to create new secrets baseline or to update an existing baseline. This is usually not necessary if a secret baseline already exists, since pre-commit will automatically install `detect-secrets` in an isolated environment for executing the pre-commit hook.


## Sample configurations

Sample configurations for pre-commit hooks. To use one of these configurations copy it to the root of your repository, rename it to `.pre-commit-config.yaml` and run `pre-commit install`.

- **basic.pre-commit-config.yaml:** basic pre-commit hook configuration with hooks to remove trailing spaces and ensure there is a newline in text files, and to check for potential secrets in committed files. To use it you first need to create a secret baseline using `detect-secrets`.
- **kotlin.pre-commit-config.yaml:** basic configuration with the addition of automatic kotlin files formatting with ktlint. Ktlint will be automatically downloaded in the pre-commit hook environment.
