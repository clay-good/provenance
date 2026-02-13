package com.provenance.keycloak.pic.resource;

import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;

/**
 * Realm resource provider for public PIC endpoints.
 *
 * <p>Returns a {@link PicRealmResource} JAX-RS resource that handles
 * public realm-level PIC operations at {@code /realms/{realm}/pic/...}.
 *
 * <p>Keycloak resolves the realm from the URL before calling
 * {@link #getResource()}.
 */
public class PicRealmResourceProvider implements RealmResourceProvider {

    private final KeycloakSession session;

    public PicRealmResourceProvider(KeycloakSession session) {
        this.session = session;
    }

    @Override
    public Object getResource() {
        RealmModel realm = session.getContext().getRealm();
        return new PicRealmResource(session, realm);
    }

    @Override
    public void close() {
        // Per-request cleanup — nothing to clean up
    }
}
