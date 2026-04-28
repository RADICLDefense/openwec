use anyhow::Result;
use async_trait::async_trait;
use deadpool_postgres::Transaction;

use crate::{database::postgres::PostgresMigration, migration};

pub(super) struct AddClientIdentityFieldsInSubscriptionsTable;
migration!(
    AddClientIdentityFieldsInSubscriptionsTable,
    16,
    "adds client_identity_strategy and client_identity_fallback_strategy fields to subscriptions table"
);

#[async_trait]
impl PostgresMigration for AddClientIdentityFieldsInSubscriptionsTable {
    async fn up(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN client_identity_strategy TEXT NOT NULL DEFAULT 'Subject'",
            &[],
        )
        .await?;
        tx.execute(
            "ALTER TABLE subscriptions ADD COLUMN client_identity_fallback_strategy TEXT",
            &[],
        )
        .await?;
        Ok(())
    }

    async fn down(&self, tx: &mut Transaction) -> Result<()> {
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN client_identity_strategy",
            &[],
        )
        .await?;
        tx.execute(
            "ALTER TABLE subscriptions DROP COLUMN client_identity_fallback_strategy",
            &[],
        )
        .await?;
        Ok(())
    }
}
