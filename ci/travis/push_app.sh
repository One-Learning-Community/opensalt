#!/bin/bash

if [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
    docker login -u $DOCKER_USER -p $DOCKER_PASS
    export REPO=opensalt/opensalt
    #  export TAG=`if [ "$TRAVIS_BRANCH" == "master" ]; then echo "latest"; else echo $(echo $TRAVIS_BRANCH | sed -e 's#/#-#g') ; fi`
    #  docker tag $REPO:$COMMIT $REPO:$TAG
    if [ "$TRAVIS_BRANCH" == "main" ]; then
        docker tag opensalt/opensalt:core-3.x $REPO:core-latest
        docker tag opensalt/opensalt:web-3.x $REPO:web-latest
        docker push $REPO:core-latest
        docker push $REPO:web-latest
    fi
    if [ "$TRAVIS_BRANCH" == "master" ]; then
        docker tag opensalt/opensalt:core-3.x $REPO:core-latest
        docker tag opensalt/opensalt:web-3.x $REPO:web-latest
        docker push $REPO:core-latest
        docker push $REPO:web-latest
    fi
    if [ "$TRAVIS_BRANCH" == "develop" ]; then
        docker tag opensalt/opensalt:core-3.x $REPO:core-develop
        docker tag opensalt/opensalt:web-3.x $REPO:web-develop
        docker push $REPO:core-develop
        docker push $REPO:web-develop
    fi
    #docker tag $REPO:$COMMIT $REPO:travis-$TRAVIS_BUILD_NUMBER
    docker rmi opensalt/opensalt:core-3.x
    docker rmi opensalt/opensalt:web-3.x
fi
