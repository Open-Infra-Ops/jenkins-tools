#!/bin/bash
set -e
IMAGE_VERSION="v0.0.1"

if hash docker 2>/dev/null; then
    # docker login -u cn-north-4@$DOCKER_USER -p $DOCKER_PASS swr.cn-north-4.myhuaweicloud.com
    docker login -u $DOCKER_USER -p $DOCKER_PASS
else
    echo "docker not installed."
    exit
fi

if hash git 2>/dev/null; then
    DOCS_VERSION=$(git rev-parse HEAD)
    IMAGE_VERSION=${DOCS_VERSION}$(date +%s)
fi


echo "#######################start to product docker image#######################"
echo "current path:"`pwd`
echo "current image version:"${IMAGE_VERSION}
cd mailman-exim
# docker build -t swr.cn-north-4.myhuaweicloud.com/opensourceway/app-mailman/mailman-exim4-build:latest .
# docker push swr.cn-north-4.myhuaweicloud.com/opensourceway/app-mailman/mailman-exim4-build:latest
# docker rmi swr.cn-north-4.myhuaweicloud.com/opensourceway/app-mailman/mailman-exim4-build:latest

docker build -t dockertomchao/mailman-exim4-build:latest .
docker push dockertomchao/mailman-exim4-build:latest
docker rmi dockertomchao/mailman-exim4-build:latest