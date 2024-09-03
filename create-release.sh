#!/bin/sh

IMAGE=$1
OLD_VERSION=$2
VERSION=$3

git checkout main
git pull

git-cliff --tag=${VERSION} --strip=header ${OLD_VERSION}.. > .tmp.release_info
git-cliff -o --tag=${VERSION} --strip=header

sed -i -e "s/^version = \"${OLD_VERSION}\"/version = \"${VERSION}\"/" Cargo.toml

cargo build

git add Cargo.lock Cargo.toml CHANGELOG.md

git commit -m "release: ${VERSION}" -s

git tag -a "${VERSION}" -F .tmp.release_info

git push
git push --tags

gh release create --verify-tag -F .tmp.release_info -t "${VERSION}" ${VERSION}

git pull

git checkout ${VERSION}

docker build --progress=plain -t "${IMAGE}:${VERSION}" .

docker tag "${IMAGE}:${VERSION}" "${IMAGE}:latest"
docker push "${IMAGE}:${VERSION}"
docker push "${IMAGE}:latest"

git checkout main
