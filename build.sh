#!/bin/sh
#
# Builds all ozone-security artifacts. To release (to Nexus) execute:
#     $ ./build.sh clean deploy
#

mvn -f ozone-security-build-all/pom.xml $*
