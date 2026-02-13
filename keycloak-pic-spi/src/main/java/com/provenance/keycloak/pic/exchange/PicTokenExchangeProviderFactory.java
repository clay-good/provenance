package com.provenance.keycloak.pic.exchange;

import com.provenance.keycloak.pic.trustplane.TrustPlaneClient;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory;

/**
 * Factory for {@link PicTokenExchangeProvider}.
 *
 * <p>This factory manages the lifecycle of the shared {@link TrustPlaneClient}
 * and creates per-request {@code PicTokenExchangeProvider} instances.
 *
 * <p><b>Registration:</b> Registered via Java ServiceLoader in
 * {@code META-INF/services/org.keycloak.protocol.oidc.TokenExchangeProviderFactory}
 *
 * <p><b>Provider selection:</b> Keycloak's {@code TokenExchangeGrantType} iterates
 * all registered factories sorted by {@link #order()} descending. It calls
 * {@code supports()} on each provider until one returns {@code true}.
 * This factory returns order 100, which is higher than the default provider's 0,
 * ensuring PIC exchange requests are handled by this provider first.
 *
 * <p><b>Lifecycle:</b>
 * <ol>
 *   <li>{@link #init(Config.Scope)} — Called once during server startup</li>
 *   <li>{@link #postInit(KeycloakSessionFactory)} — Called after all SPIs are initialized;
 *       creates the shared {@link TrustPlaneClient}</li>
 *   <li>{@link #create(KeycloakSession)} — Called per-request to create a provider instance</li>
 *   <li>{@link #close()} — Called during server shutdown; closes the {@link TrustPlaneClient}</li>
 * </ol>
 */
public class PicTokenExchangeProviderFactory implements TokenExchangeProviderFactory {

    private static final Logger LOG = Logger.getLogger(PicTokenExchangeProviderFactory.class);

    /**
     * Provider ID used for Keycloak's SPI registry.
     */
    public static final String PROVIDER_ID = "pic-token-exchange";

    /**
     * Shared Trust Plane HTTP client.
     * Thread-safe, shared across all request threads.
     */
    private TrustPlaneClient trustPlaneClient;

    @Override
    public TokenExchangeProvider create(KeycloakSession session) {
        return new PicTokenExchangeProvider(session, trustPlaneClient);
    }

    @Override
    public void init(Config.Scope config) {
        LOG.info("Initializing PIC Token Exchange Provider Factory");
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
        this.trustPlaneClient = new TrustPlaneClient();
        LOG.info("PIC Token Exchange Provider Factory initialized with TrustPlaneClient");
    }

    @Override
    public void close() {
        if (trustPlaneClient != null) {
            trustPlaneClient.close();
            LOG.info("PIC Token Exchange Provider Factory closed");
        }
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    /**
     * Returns the provider order (priority).
     *
     * <p>Higher order = higher priority. The default Keycloak token exchange
     * provider has order 0. We use 100 to ensure PIC exchange requests
     * are evaluated by this provider first. If {@code supports()} returns
     * {@code false} (e.g., non-PIC exchange), Keycloak falls through to
     * the default provider.
     *
     * @return 100
     */
    @Override
    public int order() {
        return 100;
    }
}
