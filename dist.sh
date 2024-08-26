#!/bin/sh

VERSION=$1

# mkdir -p "dist/${VERSION}"
# zola -r ./support-site/ build -o "dist/${VERSION}/support-site-www/"

# mkdir -p "dist/${VERSION}/www"
# cp -rfv ./static/ "dist/${VERSION}/www"

docker build --progress=plain -t "sjc.vultrcr.com/ngerakines/badgeblue:${VERSION}" .

docker tag "sjc.vultrcr.com/ngerakines/badgeblue:${VERSION}" "sjc.vultrcr.com/ngerakines/badgeblue:latest"
docker push "sjc.vultrcr.com/ngerakines/badgeblue:${VERSION}"
docker push "sjc.vultrcr.com/ngerakines/badgeblue:latest"

# zip -r "dist/atprotocamp-${VERSION}.zip" "dist/${VERSION}"
