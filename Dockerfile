# Build stage
FROM maven:3.9.9-eclipse-temurin-21 AS build
COPY src /home/app/src
COPY pom.xml /home/app
RUN mvn -f /home/app/pom.xml clean package -DskipTests
COPY docker /home/app/docker

# Package stage
FROM eclipse-temurin:21-jre-alpine

# add non root user cscapi
RUN addgroup --system --gid 10001 cscapi && adduser --system --home /opt/cscapi --uid 10001 --ingroup cscapi cscapi

COPY --from=build /home/app/docker /
COPY --from=build /home/app/target/*.jar /opt/cscapi/app.jar

WORKDIR /opt/cscapi

ENV PORT=8080
ENV TRUSTED_CERTIFICATES=
ENV REMOTE_DEBUG=false

ENV HTTP_PROXY=
ENV HTTPS_PROXY=
ENV NO_PROXY=

USER 10001

ENTRYPOINT ["/opt/cscapi/entry.sh"]
