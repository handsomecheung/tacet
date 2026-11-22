use crate::daemon::DaemonClient;
use std::io::{self, Write};

pub async fn execute_read(
    client: &DaemonClient,
    uri: String,
    no_newline: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client.read(&uri).await?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&resp.bytes)?;
    if !resp.is_attachment && !no_newline {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;

    Ok(())
}
