use std::collections::HashMap;

use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::scan::{self, FetchResult};

#[derive(Debug)]
enum Error {
    NotFound,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use Error::*;
        match self {
            NotFound => write!(f, "not found"),
        }
    }
}

impl std::error::Error for Error {}

#[async_trait]
trait Storage<T> {
    async fn get(&self, id: &str) -> Result<T, Error>;
    async fn insert(&self, t: T) -> Result<Option<T>, Error>;
    async fn remove(&self, id: &str) -> Result<T, Error>;
}

#[async_trait]
trait AppendFetchResult {
    async fn append_fetch_result(&self, id: &str, results: FetchResult) -> Result<(), Error>;
}

struct ScanProgressInMemoryStorage<E> {
    scans: RwLock<HashMap<String, crate::scan::Progress>>,
    crypter: E,
}

impl Default for ScanProgressInMemoryStorage<crate::crypt::ChaCha20Crypt> {
    fn default() -> Self {
        Self {
            scans: RwLock::new(HashMap::new()),
            crypter: crate::crypt::ChaCha20Crypt::default(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct Progress {
    /// The scan that is being tracked. The credentials passwords are encrypted.
    scan: models::Scan,
    /// The status of the scan. Does not need to be encrypted.
    status: models::Status,
    /// The results of the scan as encrypted json.
    ///
    /// The reason that it is json is that we don't need it unless it is requested by the user.
    results: Vec<Vec<u8>>,
}

#[async_trait]
impl<E> Storage<scan::Progress> for ScanProgressInMemoryStorage<E>
where
    E: crate::crypt::Crypt + Send + Sync + 'static,
{
    async fn get(&self, id: &str) -> Result<scan::Progress, Error> {
        self.scans
            .read()
            .await
            .get(id)
            .map(|p| p.clone())
            .ok_or(Error::NotFound)
    }

    async fn insert(&self, t: scan::Progress) -> Result<Option<scan::Progress>, Error> {
        Ok(self.scans.write().await.insert(t.id().to_string(), t))
    }

    async fn remove(&self, id: &str) -> Result<scan::Progress, Error> {
        self.scans.write().await.remove(id).ok_or(Error::NotFound)
    }
}

#[cfg(test)]
mod tests {
    use models::Scan;

    use super::*;

    #[tokio::test]
    async fn in_memory_storage() {
        let storage = ScanProgressInMemoryStorage::default();
        let scan = Scan::default();
        let id = scan.scan_id.clone().unwrap();
        let inserted = storage.insert(scan.into()).await.unwrap();
        assert!(inserted.is_none());
        let retrieved = storage.get(&id).await.unwrap();
        assert_eq!(retrieved.id(), id);
        let removed = storage.remove(&id).await.unwrap();
        assert_eq!(removed.id(), id);
    }
}
