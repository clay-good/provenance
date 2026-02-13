package com.provenance.keycloak.pic.admin;

import com.provenance.keycloak.pic.trustplane.TrustPlaneClient;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory;

/**
 * Factory for {@link PicAdminResourceProvider}.
 *
 * <p>The {@link #getId()} return value determines the URL path segment:
 * {@code /admin/realms/{realm}/pic/...}
 *
 * <p>Manages the shared {@link TrustPlaneClient} lifecycle for admin endpoints
 * that need to communicate with the Trust Plane (status check, key management).
 *
 * <p><b>Registration:</b> Registered via Java ServiceLoader in
 * {@code META-INF/services/org.keycloak.services.resources.admin.ext.AdminRealmResourceProviderFactory}
 */
public class PicAdminResourceProviderFactory implements AdminRealmResourceProviderFactory {

    private static final Logger LOG = Logger.getLogger(PicAdminResourceProviderFactory.class);

    /**
     * Provider ID — becomes the URL path segment under /admin/realms/{realm}/.
     */
    public static final String PROVIDER_ID = "pic";

    private TrustPlaneClient trustPlaneClient;

    @Override
    public PicAdminResourceProvider create(KeycloakSession session) {
        return new PicAdminResourceProvider(trustPlaneClient);
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("Initializing PIC Admin Resource Provider Factory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.trustPlaneClient = new TrustPlaneClient();
        LOG.info("PIC Admin Resource Provider Factory initialized with TrustPlaneClient");
    }

    @Override
    public void close() {
        if (trustPlaneClient != null) {
            trustPlaneClient.close();
            LOG.info("PIC Admin Resource Provider Factory closed");
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
