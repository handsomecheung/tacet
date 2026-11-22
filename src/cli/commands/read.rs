use crate::daemon::DaemonClient;
use std::io::{self, Write};

pub async fn execute_read(
    client: &DaemonClient,
    uri: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.read(&uri).await?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&resp.bytes)?;
    stdout.flush()?;

    Ok(())
}
