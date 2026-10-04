# syntax=docker/dockerfile:1
ARG PINGFEDERATE_IMAGE_TAG=2511-12.3.3

# The PingFederate image doubles as the SDK: the plugin compiles against the jars it runs with.
FROM pingidentity/pingfederate:${PINGFEDERATE_IMAGE_TAG} AS pingfederate

# ---- build the Biscuit token generator plugin ------------------------------------------------
# JDK 11 matches the plugin's release level. The SDK tests bootstrap PingFederate internals that
# need extra --add-opens on 17+.
FROM maven:3.9-eclipse-temurin-11 AS plugin-build
ARG SKIP_TESTS=false
COPY --from=pingfederate /opt/server/server/default/lib /pf/server/default/lib
WORKDIR /build
# "plugin" is a named build context (see additional_contexts in docker-compose.yaml).
# The cache mount keeps ~/.m2 between builds, so dependencies are only downloaded once.
COPY --from=plugin pom.xml .
COPY --from=plugin src ./src
RUN --mount=type=cache,target=/root/.m2 mvn -B -Dpf.home=/pf -DskipTests=${SKIP_TESTS} package

# ---- PingFederate with the plugin deployed ---------------------------------------------------
FROM pingidentity/pingfederate:${PINGFEDERATE_IMAGE_TAG}
COPY --from=plugin-build --chown=ping:root \
     /build/target/pf.plugins.biscuit-token-generator.jar \
     /opt/server/server/default/deploy/
