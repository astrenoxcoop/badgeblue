# Development

Guidelines:

* Use conventional commits for everything. https://www.conventionalcommits.org/en/v1.0.0/
* Use feature branches when possible, but main is fine too.

## Creating Releases

1. Use the create-release.sh script to package the container.

    $ ./create-release.sh sjc.vultrcr.com/ngerakines/badgeblue 0.2.2 0.2.3

2. Use the release.sh script to complete the release process server-side:

    $ ssh -v vultr 'sudo /var/lib/badgeblue/release.sh 0.2.3'

