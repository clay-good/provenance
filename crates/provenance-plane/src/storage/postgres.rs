//! PostgreSQL storage backend
//!
//! Persistent storage implementation using PostgreSQL.
//! Required for federation and high-availability deployments.
//!
//! # Setup
//!
//! Create the database and tables:
//! ```sql
//! CREATE DATABASE provenance_plane;
//!
//! -- See migrations below for table creation
//! ```
//!
//! # Environment Variables
//!
//! - `DATABASE_URL`: PostgreSQL connection string
//!   e.g., `postgres://user:pass@localhost/provenance_plane`

use async_trait::async_trait;
use sqlx::{postgres::PgPoolOptions, PgPool, Row};
use tracing::{error, info};

use super::{CatInfo, ExecutorInfo, KeyStore, RevocationEntry, StorageError};

/// PostgreSQL key store implementation
#[derive(Debug, Clone)]
pub struct PostgresStore {
    pool: PgPool,
}

impl PostgresStore {
    /// Create a new PostgreSQL store from a connection string
    pub async fn new(database_url: &str) -> Result<Self, StorageError> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await
            .map_err(|e| StorageError::Connection(e.to_string()))?;

        info!("Connected to PostgreSQL database");

        let store = Self { pool };

        // Run migrations
        store.run_migrations().await?;

        Ok(store)
    }

    /// Create from an existing pool
    pub fn from_pool(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Run database migrations
    async fn run_migrations(&self) -> Result<(), StorageError> {
        // Create tables if they don't exist
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS executor_keys (
                kid VARCHAR(255) PRIMARY KEY,
                public_key BYTEA NOT NULL,
                service_name VARCHAR(255),
                registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ
            );

            CREATE TABLE IF NOT EXISTS cat_keys (
                kid VARCHAR(255) PRIMARY KEY,
                public_key BYTEA NOT NULL,
                name VARCHAR(255),
                endpoint VARCHAR(512),
                registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                is_local BOOLEAN NOT NULL DEFAULT FALSE
            );

            CREATE TABLE IF NOT EXISTS revocations (
                id SERIAL PRIMARY KEY,
                pca_hash BYTEA NOT NULL,
                principal VARCHAR(255),
                reason VARCHAR(512) NOT NULL,
                revoked_by VARCHAR(255) NOT NULL,
                revoked_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            );

            CREATE INDEX IF NOT EXISTS idx_revocations_pca_hash ON revocations(pca_hash);
            CREATE INDEX IF NOT EXISTS idx_revocations_principal ON revocations(principal);
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        info!("Database migrations complete");
        Ok(())
    }

    /// Get the connection pool for direct access if needed
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}

#[async_trait]
impl KeyStore for PostgresStore {
    // =========================================================================
    // Executor Key Management
    // =========================================================================

    async fn register_executor(&self, info: ExecutorInfo) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO executor_keys (kid, public_key, service_name, registered_at, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (kid) DO UPDATE SET
                public_key = EXCLUDED.public_key,
                service_name = EXCLUDED.service_name,
                registered_at = EXCLUDED.registered_at,
                expires_at = EXCLUDED.expires_at
            "#,
        )
        .bind(&info.kid)
        .bind(&info.public_key)
        .bind(&info.service_name)
        .bind(&info.registered_at)
        .bind(&info.expires_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(kid = %info.kid, error = %e, "Failed to register executor");
            StorageError::Database(e.to_string())
        })?;

        info!(kid = %info.kid, "Registered executor key in database");
        Ok(())
    }

    async fn get_executor(&self, kid: &str) -> Result<Option<ExecutorInfo>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT kid, public_key, service_name, registered_at, expires_at
            FROM executor_keys
            WHERE kid = $1
              AND (expires_at IS NULL OR expires_at > NOW())
            "#,
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.map(|r| ExecutorInfo {
            kid: r.get("kid"),
            public_key: r.get("public_key"),
            service_name: r.get("service_name"),
            registered_at: r.get("registered_at"),
            expires_at: r.get("expires_at"),
        }))
    }

    async fn unregister_executor(&self, kid: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM executor_keys WHERE kid = $1")
            .bind(kid)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let removed = result.rows_affected() > 0;
        if removed {
            info!(kid = %kid, "Unregistered executor key from database");
        }
        Ok(removed)
    }

    async fn list_executors(&self) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT kid FROM executor_keys
            WHERE expires_at IS NULL OR expires_at > NOW()
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(rows.iter().map(|r| r.get("kid")).collect())
    }

    // =========================================================================
    // CAT Key Management
    // =========================================================================

    async fn register_cat(&self, info: CatInfo) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO cat_keys (kid, public_key, name, endpoint, registered_at, is_local)
            VALUES ($1, $2, $3, $4, $5, $6)
            ON CONFLICT (kid) DO UPDATE SET
                public_key = EXCLUDED.public_key,
                name = EXCLUDED.name,
                endpoint = EXCLUDED.endpoint,
                is_local = EXCLUDED.is_local
            "#,
        )
        .bind(&info.kid)
        .bind(&info.public_key)
        .bind(&info.name)
        .bind(&info.endpoint)
        .bind(&info.registered_at)
        .bind(info.is_local)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(kid = %info.kid, error = %e, "Failed to register CAT");
            StorageError::Database(e.to_string())
        })?;

        info!(
            kid = %info.kid,
            name = ?info.name,
            is_local = info.is_local,
            "Registered CAT key in database"
        );
        Ok(())
    }

    async fn get_cat(&self, kid: &str) -> Result<Option<CatInfo>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT kid, public_key, name, endpoint, registered_at, is_local
            FROM cat_keys
            WHERE kid = $1
            "#,
        )
        .bind(kid)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.map(|r| CatInfo {
            kid: r.get("kid"),
            public_key: r.get("public_key"),
            name: r.get("name"),
            endpoint: r.get("endpoint"),
            registered_at: r.get("registered_at"),
            is_local: r.get("is_local"),
        }))
    }

    async fn unregister_cat(&self, kid: &str) -> Result<bool, StorageError> {
        let result = sqlx::query("DELETE FROM cat_keys WHERE kid = $1 AND is_local = FALSE")
            .bind(kid)
            .execute(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        let removed = result.rows_affected() > 0;
        if removed {
            info!(kid = %kid, "Unregistered CAT key from database");
        }
        Ok(removed)
    }

    async fn list_cats(&self) -> Result<Vec<String>, StorageError> {
        let rows = sqlx::query("SELECT kid FROM cat_keys")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(rows.iter().map(|r| r.get("kid")).collect())
    }

    async fn list_federated_cats(&self) -> Result<Vec<CatInfo>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT kid, public_key, name, endpoint, registered_at, is_local
            FROM cat_keys
            WHERE is_local = FALSE
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|r| CatInfo {
                kid: r.get("kid"),
                public_key: r.get("public_key"),
                name: r.get("name"),
                endpoint: r.get("endpoint"),
                registered_at: r.get("registered_at"),
                is_local: r.get("is_local"),
            })
            .collect())
    }

    // =========================================================================
    // Revocation Management
    // =========================================================================

    async fn revoke(&self, entry: RevocationEntry) -> Result<(), StorageError> {
        sqlx::query(
            r#"
            INSERT INTO revocations (pca_hash, principal, reason, revoked_by, revoked_at)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(&entry.pca_hash)
        .bind(&entry.principal)
        .bind(&entry.reason)
        .bind(&entry.revoked_by)
        .bind(&entry.revoked_at)
        .execute(&self.pool)
        .await
        .map_err(|e| {
            error!(error = %e, "Failed to add revocation");
            StorageError::Database(e.to_string())
        })?;

        info!(
            principal = ?entry.principal,
            reason = %entry.reason,
            "Added revocation to database"
        );
        Ok(())
    }

    async fn is_revoked(&self, pca_hash: &[u8]) -> Result<bool, StorageError> {
        let row = sqlx::query("SELECT 1 FROM revocations WHERE pca_hash = $1 LIMIT 1")
            .bind(pca_hash)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn is_principal_revoked(&self, principal: &str) -> Result<bool, StorageError> {
        let row = sqlx::query("SELECT 1 FROM revocations WHERE principal = $1 LIMIT 1")
            .bind(principal)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.is_some())
    }

    async fn get_revocation(&self, pca_hash: &[u8]) -> Result<Option<RevocationEntry>, StorageError> {
        let row = sqlx::query(
            r#"
            SELECT pca_hash, principal, reason, revoked_by, revoked_at
            FROM revocations
            WHERE pca_hash = $1
            LIMIT 1
            "#,
        )
        .bind(pca_hash)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(row.map(|r| RevocationEntry {
            pca_hash: r.get("pca_hash"),
            principal: r.get("principal"),
            reason: r.get("reason"),
            revoked_by: r.get("revoked_by"),
            revoked_at: r.get("revoked_at"),
        }))
    }

    async fn list_revocations(&self) -> Result<Vec<RevocationEntry>, StorageError> {
        let rows = sqlx::query(
            r#"
            SELECT pca_hash, principal, reason, revoked_by, revoked_at
            FROM revocations
            ORDER BY revoked_at DESC
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| StorageError::Database(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|r| RevocationEntry {
                pca_hash: r.get("pca_hash"),
                principal: r.get("principal"),
                reason: r.get("reason"),
                revoked_by: r.get("revoked_by"),
                revoked_at: r.get("revoked_at"),
            })
            .collect())
    }
}
