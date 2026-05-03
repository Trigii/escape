# Minimal local image used by every lab service.
# The helper binary is built on the host so startup does not depend on
# pulling a base image from Docker Hub.
FROM scratch
COPY .lab-keepalive /lab-keepalive
ENTRYPOINT ["/lab-keepalive"]
