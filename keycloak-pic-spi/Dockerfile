FROM quay.io/keycloak/keycloak:26.0 AS builder

COPY target/keycloak-pic-spi-*.jar /opt/keycloak/providers/

RUN /opt/keycloak/bin/kc.sh build \
    --features=token-exchange,admin-fine-grained-authz

FROM quay.io/keycloak/keycloak:26.0

COPY --from=builder /opt/keycloak/ /opt/keycloak/

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
