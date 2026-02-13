package com.provenance.keycloak.pic.resource;

import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * Factory for {@link PicRealmResourceProvider}.
 *
 * <p>The {@link #getId()} return value determines the URL path segment:
 * {@code /realms/{realm}/pic/...}
 *
 * <p><b>Registration:</b> Registered via Java ServiceLoader in
 * {@code META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory}
 */
public class PicRealmResourceProviderFactory implements RealmResourceProviderFactory {

    private static final Logger LOG = Logger.getLogger(PicRealmResourceProviderFactory.class);

    /**
     * Provider ID — becomes the URL path segment under /realms/{realm}/.
     */
    public static final String PROVIDER_ID = "pic";

    @Override
    public PicRealmResourceProvider create(KeycloakSession session) {
        return new PicRealmResourceProvider(session);
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("Initializing PIC Realm Resource Provider Factory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        LOG.info("PIC Realm Resource Provider Factory initialized");
    }

    @Override
    public void close() {
        LOG.info("PIC Realm Resource Provider Factory closed");
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
