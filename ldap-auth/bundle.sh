#!/bin/sh

PATH=$PATH:~/packages/apache-maven-3.6.2/bin
VERSION=0.1
PACKAGE_NAME=cschultz-ldap-auth
BUILD_CLIENT=no
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

jarsigner -keystore keystore.p12 -storetype PKCS12 -storepass changeit "target/${PACKAGE_JAR}" mirth-client-plugins

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

zip -r9 "target/${PACKAGE_ZIP}" "${PACKAGE_NAME}"

rm -rf "${PACKAGE_NAME}"

