#!/bin/sh

OLD_VERSION=$1
VERSION=$2

git checkout main
git pull

git-cliff --tag=${VERSION} --strip=header ${OLD_VERSION}.. > .tmp.release_info
git-cliff -o --tag=${VERSION} --strip=header ${OLD_VERSION}..

sed -i -e "s/^version = \"${OLD_VERSION}\"/version = \"${VERSION}\"/" Cargo.toml

cargo build

git add Cargo.lock Cargo.toml CHANGELOG.md

git commit -m "release: ${VERSION}" -s

git tag -a "${VERSION}" -F .tmp.release_info

git push
git push --tags

gh release create --verify-tag -F .tmp.release_info ${VERSION}

git pull

git checkout ${VERSION}

docker build --progress=plain -t "sjc.vultrcr.com/ngerakines/badgeblue:${VERSION}" .

docker tag "sjc.vultrcr.com/ngerakines/badgeblue:${VERSION}" "sjc.vultrcr.com/ngerakines/badgeblue:latest"
docker push "sjc.vultrcr.com/ngerakines/badgeblue:${VERSION}"
docker push "sjc.vultrcr.com/ngerakines/badgeblue:latest"

git checkout main
