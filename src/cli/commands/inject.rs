use crate::daemon::DaemonClient;
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

const PLACEHOLDER_PATTERN: &str = r"\{\{\s*(tacet://[^\s}]+)\s*\}\}";

pub async fn execute_inject(
    client: &DaemonClient,
    input: Option<PathBuf>,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Read input template
    let content = match input {
        Some(path) => fs::read_to_string(&path)?,
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf)?;
            buf
        }
    };

    let rendered = render_template(client, &content).await?.unwrap_or(content);

    match output {
        Some(path) => {
            fs::write(path, rendered)?;
        }
        None => {
            print!("{rendered}");
            io::stdout().flush()?;
        }
    }

    Ok(())
}

/// Replace a single template atomically, skipping symlinks and files without placeholders.
pub async fn execute_inject_file_in_place(
    client: &DaemonClient,
    input: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let file_type = fs::symlink_metadata(&input)?.file_type();
    if file_type.is_symlink() {
        return Ok(());
    }
    if !file_type.is_file() {
        return Err(format!("input is not a regular file: {}", input.display()).into());
    }
    let input = input.canonicalize()?;
    let content = fs::read_to_string(&input)?;
    if let Some(rendered) = render_template(client, &content).await? {
        write_private_file(&input, rendered.as_bytes(), true)?;
    }
    Ok(())
}

/// Resolve all references before returning rendered text; `None` means no placeholders.
async fn render_template(
    client: &DaemonClient,
    content: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let re = Regex::new(PLACEHOLDER_PATTERN)?;
    let mut uris_set = HashSet::new();
    for cap in re.captures_iter(content) {
        if let Some(matched_uri) = cap.get(1) {
            uris_set.insert(matched_uri.as_str().to_string());
        }
    }

    if uris_set.is_empty() {
        return Ok(None);
    }

    let resolve_resp = client.resolve(uris_set.into_iter().collect()).await?;
    Ok(Some(
        re.replace_all(content, |caps: &regex::Captures| {
            resolve_resp
                .secrets
                .get(&caps[1])
                .cloned()
                .unwrap_or_else(|| caps[0].to_string())
        })
        .into_owned(),
    ))
}

/// A file discovered while walking the input directory.
enum Entry {
    /// UTF-8 file containing at least one placeholder.
    Template(String),
    /// File copied byte-for-byte (only with `--copy-all`).
    Raw(Vec<u8>),
}

/// Resolve `path` to an absolute path, canonicalizing the deepest existing ancestor.
fn absolute_resolved(path: &Path) -> io::Result<PathBuf> {
    let abs = std::path::absolute(path)?;
    let mut existing = abs.clone();
    let mut rest: Vec<std::ffi::OsString> = Vec::new();
    while !existing.exists() {
        match existing.file_name() {
            Some(name) => rest.push(name.to_os_string()),
            None => break,
        }
        if !existing.pop() {
            break;
        }
    }
    let mut resolved = existing.canonicalize()?;
    for name in rest.into_iter().rev() {
        if name != Component::CurDir.as_os_str() {
            resolved.push(name);
        }
    }
    Ok(resolved)
}

fn walk_dir(
    dir: &Path,
    rel: &Path,
    re: &Regex,
    copy_all: bool,
    out: &mut Vec<(PathBuf, Entry)>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut children: Vec<_> = fs::read_dir(dir)?.collect::<Result<_, _>>()?;
    children.sort_by_key(|e| e.file_name());
    for child in children {
        let path = child.path();
        let child_rel = rel.join(child.file_name());
        let file_type = fs::symlink_metadata(&path)?.file_type();
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            walk_dir(&path, &child_rel, re, copy_all, out)?;
        } else if file_type.is_file() {
            let bytes = fs::read(&path)?;
            match String::from_utf8(bytes) {
                Ok(text) if re.is_match(&text) => out.push((child_rel, Entry::Template(text))),
                Ok(text) if copy_all => out.push((child_rel, Entry::Raw(text.into_bytes()))),
                Err(e) if copy_all => out.push((child_rel, Entry::Raw(e.into_bytes()))),
                _ => {}
            }
        }
    }
    Ok(())
}

fn write_private_file(path: &Path, data: &[u8], force: bool) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    if !force && path.exists() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("output file already exists: {}", path.display()),
        ));
    }
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let tmp = parent.join(format!(".{name}.tacet-tmp-{}", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = (|| {
        f.write_all(data)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Recursively render every template under `in_dir` into `out_dir`.
pub async fn execute_inject_dir(
    client: &DaemonClient,
    in_dir: PathBuf,
    out_dir: PathBuf,
    force: bool,
    copy_all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    render_inject_dir(client, in_dir, Some(out_dir), force, copy_all).await
}

/// Replace templates under `in_dir` with rendered files, leaving other files untouched.
pub async fn execute_inject_dir_in_place(
    client: &DaemonClient,
    in_dir: PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    render_inject_dir(client, in_dir, None, true, false).await
}

async fn render_inject_dir(
    client: &DaemonClient,
    in_dir: PathBuf,
    out_dir: Option<PathBuf>,
    force: bool,
    copy_all: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if !in_dir.is_dir() {
        return Err(format!("input is not a directory: {}", in_dir.display()).into());
    }
    let in_abs = in_dir.canonicalize()?;
    let out_abs = match out_dir {
        Some(path) => {
            let out_abs = absolute_resolved(&path)?;
            if out_abs.starts_with(&in_abs) {
                return Err("output directory must not be inside the input directory".into());
            }
            out_abs
        }
        None => in_abs.clone(),
    };

    // 1. Discover files
    let re = Regex::new(PLACEHOLDER_PATTERN)?;
    let mut entries = Vec::new();
    walk_dir(&in_abs, Path::new(""), &re, copy_all, &mut entries)?;

    // 2. Refuse to overwrite existing outputs unless forced (before writing anything)
    if !force {
        for (rel, _) in &entries {
            let target = out_abs.join(rel);
            if fs::symlink_metadata(&target).is_ok() {
                return Err(format!(
                    "output file already exists (use --force to overwrite): {}",
                    target.display()
                )
                .into());
            }
        }
    }

    // 3. Fail-fast: batch resolve all URIs across all files
    let mut uris_set = HashSet::new();
    for (_, entry) in &entries {
        if let Entry::Template(text) = entry {
            for cap in re.captures_iter(text) {
                uris_set.insert(cap[1].to_string());
            }
        }
    }
    let secrets = if uris_set.is_empty() {
        Default::default()
    } else {
        client
            .resolve(uris_set.into_iter().collect())
            .await?
            .secrets
    };

    // 4. Render and write
    for (rel, entry) in entries {
        let target = out_abs.join(&rel);
        let data = match entry {
            Entry::Template(text) => re
                .replace_all(&text, |caps: &regex::Captures| {
                    secrets
                        .get(&caps[1])
                        .cloned()
                        .unwrap_or_else(|| caps[0].to_string())
                })
                .into_owned()
                .into_bytes(),
            Entry::Raw(bytes) => bytes,
        };
        write_private_file(&target, &data, force)?;
    }
    Ok(())
}
