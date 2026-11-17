
FROM quay.io/keycloak/keycloak:26.4

ENV KC_DB=postgres
ENV KC_HTTP_ENABLED=true
ENV KC_HTTP_PORT=10000
ENV KC_PROXY_HEADERS=xforwarded
ENV KC_HEALTH_ENABLED=true

RUN /opt/keycloak/bin/kc.sh build

EXPOSE 10000

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
