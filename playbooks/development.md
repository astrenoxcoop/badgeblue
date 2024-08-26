# Development

## Feature Development

1. Deveop in branches created from issues.

2. Commit using https://www.conventionalcommits.org/en/v1.0.0/

3. Update the changelog with `git-cliff -o`

## Release Prep

On main:

1. Bump the version in `Cargo.toml`

2. Update the changelog with `git-cliff -o --bump`

3. Commit the version and changelog changes.

4. Create a GitHub release using that version.
