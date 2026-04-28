use anyhow::{anyhow, Result};
use rusqlite::Connection;

use crate::database::sqlite::SQLiteMigration;
use crate::migration;

pub(super) struct AddClientIdentityFieldsInSubscriptionsTable;
migration!(
    AddClientIdentityFieldsInSubscriptionsTable,
    15,
    "adds client_identity_strategy and client_identity_fallback_strategy fields to subscriptions table"
);

impl SQLiteMigration for AddClientIdentityFieldsInSubscriptionsTable {
    fn up(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN client_identity_strategy TEXT NOT NULL DEFAULT 'Subject'",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute(
            "ALTER TABLE subscriptions ADD COLUMN client_identity_fallback_strategy TEXT",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }

    fn down(&self, conn: &Connection) -> Result<()> {
        conn.execute(
            "ALTER TABLE subscriptions DROP COLUMN client_identity_strategy",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        conn.execute(
            "ALTER TABLE subscriptions DROP COLUMN client_identity_fallback_strategy",
            [],
        )
        .map_err(|err| anyhow!("SQLiteError: {}", err))?;
        Ok(())
    }
}
