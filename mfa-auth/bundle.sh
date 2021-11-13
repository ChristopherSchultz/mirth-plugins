#!/bin/sh

PATH=$PATH:~/packages/apache-maven-3.6.2/bin
VERSION=0.1
PACKAGE_NAME=cschultz-mfa-auth
BUILD_CLIENT=yes
BUILD_SERVER=yes

PACKAGE_JAR=${PACKAGE_NAME}-${VERSION}.jar
CLIENT_JAR=${PACKAGE_NAME}-client.jar
SERVER_JAR=${PACKAGE_NAME}-server.jar
PACKAGE_ZIP="${PACKAGE_NAME}-${VERSION}.zip"

rm -f "target/${PACKAGE_ZIP}"

mvn package

status=$?

if [ "0" != "$status" ] ; then
  exit
fi

jarsigner -tsa 'http://timestamp.digicert.com' -keystore keystore.p12 -storetype PKCS12 -storepass changeit "target/${PACKAGE_JAR}" mirth-client-plugins

# Use a separate directory for ZIP assembly
rm -rf "${PACKAGE_NAME}"
mkdir -p "${PACKAGE_NAME}"
if [ "yes" == "${BUILD_SERVER}" ] ; then
  cp -a "target/${PACKAGE_JAR}" "${PACKAGE_NAME}/${SERVER_JAR}"
fi
if [ "yes" == "${BUILD_CLIENT}" ] ; then
  cp -a "target/${PACKAGE_JAR}" "${PACKAGE_NAME}/${CLIENT_JAR}"
fi
cp -a src/main/resources/plugin.xml "${PACKAGE_NAME}/plugin.xml"
cp -a libs/java-totp-1.1.jar "${PACKAGE_NAME}"
cp -a README.md "${PACKAGE_NAME}"

zip -r9 "target/${PACKAGE_ZIP}" "${PACKAGE_NAME}"

rm -rf "${PACKAGE_NAME}"

