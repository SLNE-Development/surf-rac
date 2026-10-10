//! Health check and schema tests.

mod common;

use sqlx::PgPool;

/// The health endpoint answers 200.
#[sqlx::test(migrations = "./migrations")]
async fn healthz_ok(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.client.get(app.url("/healthz")).send().await.unwrap();
    assert_eq!(res.status(), 200);
}

/// The migrations create every expected table, each empty.
#[sqlx::test(migrations = "./migrations")]
async fn migrations_create_tables(pool: PgPool) {
    for table in ["users", "sessions", "devices", "device_links", "contacts"] {
        let count: i64 = sqlx::query_scalar(&format!("select count(*) from {table}"))
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 0, "{table}");
    }
}

/// An unknown route answers 404.
#[sqlx::test(migrations = "./migrations")]
async fn unknown_route_404(pool: PgPool) {
    let app = common::spawn(pool).await;
    let res = app.client.get(app.url("/nope")).send().await.unwrap();
    assert_eq!(res.status(), 404);
}
