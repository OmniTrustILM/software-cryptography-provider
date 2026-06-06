# Build stage
FROM maven:3.9.14-eclipse-temurin-21 AS build

COPY src /home/app/src
COPY pom.xml /home/app

RUN mvn -f /home/app/pom.xml clean package
COPY docker /home/app/docker

# Package stage
FROM eclipse-temurin:26-jre-alpine

LABEL org.opencontainers.image.authors="CZERTAINLY <support@czertainly.com>"

# add non root user czertainly
RUN addgroup --system --gid 10001 czertainly && adduser --system --home /opt/czertainly --uid 10001 --ingroup czertainly czertainly

COPY --from=build /home/app/docker /
COPY --from=build /home/app/target/*.jar /opt/czertainly/app.jar

WORKDIR /opt/czertainly

ENV JDBC_URL=
ENV JDBC_USERNAME=
ENV JDBC_PASSWORD=
ENV DB_SCHEMA=softcp
ENV PORT=8080
ENV TOKEN_DELETE_ON_REMOVE=false
ENV JAVA_OPTS=

USER 10001

ENTRYPOINT ["/opt/czertainly/entry.sh"]
