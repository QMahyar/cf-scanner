use std::future::Future;
use std::pin::Pin;

pub(super) struct FakeSub(pub(super) &'static str);

impl crate::configs::SubFetch for FakeSub {
    fn fetch(
        &self,
        _url: &str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        Box::pin(async move { Ok(self.0.to_owned()) })
    }
}
