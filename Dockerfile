# Build stage
FROM maven:3.9.16-eclipse-temurin-21 AS build

COPY src /home/app/src
COPY pom.xml /home/app
COPY docker /home/app/docker

# Tests run here on purpose. publish_docker.yaml and build.yml are independent workflows on
# the same main/tag push, so nothing else stops a failing build from being published:
# skipping tests here would let the publish job push and sign an image while the test
# workflow is still running or already red. This stage is the only thing gating that.
RUN mvn -f /home/app/pom.xml clean package

# Optimize stage
FROM eclipse-temurin:21-jdk-alpine AS optimize

COPY --from=build /home/app/target/*.jar /app/app.jar

WORKDIR /app

RUN jar xf app.jar
RUN jdeps \
    --ignore-missing-deps \
    --print-module-deps \
    --multi-release 21 \
    --recursive \
    --class-path 'BOOT-INF/lib/*' \
    app.jar > modules.txt

# Create a custom Java runtime.
#
# jdeps derives the module list from bytecode references, so a module reached only through
# ServiceLoader has to be named here.
#
#   jdk.crypto.ec  SunEC. JSSE needs it for the ECDHE key exchange that TLS 1.3 always uses,
#                  so a JDBC URL requiring TLS fails with handshake_failure without it and
#                  the connector does not start. The key operations do not need it; they name
#                  BouncyCastle.
#
# Add to ADDITIONAL_MODULES rather than editing the jlink invocation, and say what needs it.
ENV ADDITIONAL_MODULES=jdk.crypto.ec
RUN $JAVA_HOME/bin/jlink \
    --add-modules $(cat modules.txt),${ADDITIONAL_MODULES} \
    --strip-debug \
    --no-man-pages \
    --no-header-files \
    --compress=zip-6 \
    --output /javaruntime

# Package stage
FROM alpine:3.24

ENV JAVA_HOME=/opt/jre
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# copy optimized JRE
COPY --from=optimize /javaruntime $JAVA_HOME

LABEL org.opencontainers.image.authors="ILM <ilm@omnitrust.com>"

# apply outstanding Alpine security updates on top of the base image
RUN apk --no-cache upgrade

# add non root user software-cryptography-provider
RUN addgroup --system --gid 10001 software-cryptography-provider \
 && adduser --system --home /opt/software-cryptography-provider --uid 10001 \
    --ingroup software-cryptography-provider software-cryptography-provider

COPY --from=build /home/app/docker /
COPY --from=build /home/app/target/*.jar /opt/software-cryptography-provider/app.jar

WORKDIR /opt/software-cryptography-provider

ENV JDBC_URL=
ENV JDBC_USERNAME=
ENV JDBC_PASSWORD=
ENV DB_SCHEMA=softcp
ENV PORT=8080
ENV TOKEN_DELETE_ON_REMOVE=false
ENV JAVA_OPTS=

USER 10001

ENTRYPOINT ["/opt/software-cryptography-provider/entry.sh"]
