@ECHO OFF
GOTO RunScript

Builds all ozone-security artifacts. To release (to Nexus) execute:
    > build.bat clean deploy

:RunScript

mvn -f build-all-pom.xml %*
