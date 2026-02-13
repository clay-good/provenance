package com.provenance.keycloak.pic.admin;

import com.provenance.keycloak.pic.trustplane.TrustPlaneClient;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resources.admin.AdminEventBuilder;
import org.keycloak.services.resources.admin.ext.AdminRealmResourceProvider;
import org.keycloak.services.resources.admin.permissions.AdminPermissionEvaluator;

/**
 * Admin realm resource provider for PIC configuration endpoints.
 *
 * <p>Returns a {@link PicAdminResource} JAX-RS resource that handles
 * admin-level PIC operations at {@code /admin/realms/{realm}/pic/...}.
 *
 * <p>Keycloak automatically handles admin authentication and realm resolution
 * before this provider's {@link #getResource} method is called.
 */
public class PicAdminResourceProvider implements AdminRealmResourceProvider {

    private final TrustPlaneClient trustPlaneClient;

    public PicAdminResourceProvider(TrustPlaneClient trustPlaneClient) {
        this.trustPlaneClient = trustPlaneClient;
    }

    @Override
    public Object getResource(KeycloakSession session, RealmModel realm,
                              AdminPermissionEvaluator auth,
                              AdminEventBuilder adminEvent) {
        return new PicAdminResource(session, realm, auth, trustPlaneClient);
    }

    @Override
    public void close() {
        // Per-request cleanup — nothing to clean up
    }
}
