# The binary is built by conformance.yaml's prebuild (static, CGO_ENABLED=0),
# so the image needs no base image and nothing is pulled.
FROM scratch
COPY refapp /app/refapp
COPY heain-app.yaml /app/heain-app.yaml
ENTRYPOINT ["/app/refapp"]
