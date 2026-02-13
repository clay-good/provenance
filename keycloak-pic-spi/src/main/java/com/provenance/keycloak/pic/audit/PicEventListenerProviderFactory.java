package com.provenance.keycloak.pic.audit;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.events.EventListenerProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;

/**
 * Factory for {@link PicEventListenerProvider}.
 *
 * <p>This factory creates per-request event listener instances that capture
 * PIC-relevant security events for structured audit logging.
 *
 * <p><b>Registration:</b> Registered via Java ServiceLoader in
 * {@code META-INF/services/org.keycloak.events.EventListenerProviderFactory}
 *
 * <p><b>Activation:</b> To enable PIC audit logging for a realm, add
 * {@code "pic-audit"} to the realm's Event Listeners configuration
 * in the Keycloak admin console.
 */
public class PicEventListenerProviderFactory implements EventListenerProviderFactory {

    private static final Logger LOG = Logger.getLogger(PicEventListenerProviderFactory.class);

    /**
     * Provider ID used for Keycloak's SPI registry.
     */
    public static final String PROVIDER_ID = "pic-audit";

    @Override
    public PicEventListenerProvider create(KeycloakSession session) {
        return new PicEventListenerProvider();
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("Initializing PIC Event Listener Provider Factory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LOG.info("PIC Event Listener Provider Factory initialized");
    }

    @Override
    public void close() {
        LOG.info("PIC Event Listener Provider Factory closed");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
