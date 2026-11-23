use crate::daemon::DaemonClient;
use std::collections::HashSet;
use std::error::Error;

pub async fn execute_list(
    client: &DaemonClient,
    scope: Option<String>,
    search: Option<String>,
    json: bool,
) -> Result<(), Box<dyn Error>> {
    let resp = client.list(scope.as_deref(), search.as_deref()).await?;

    if json {
        let json_str = serde_json::to_string_pretty(&resp.items)?;
        println!("{json_str}");
        return Ok(());
    }

    if resp.items.is_empty() {
        println!("No items found matching the specified criteria.");
        return Ok(());
    }

    // Determine column widths
    let id_width = 36;
    let name_width = resp
        .items
        .iter()
        .map(|i| i.name.chars().count())
        .max()
        .unwrap_or(4)
        .clamp(4, 40);
    let scope_width = resp
        .items
        .iter()
        .map(|i| i.scope.chars().count())
        .max()
        .unwrap_or(5)
        .clamp(5, 30);
    let type_width = resp
        .items
        .iter()
        .map(|i| i.cipher_type.chars().count())
        .max()
        .unwrap_or(4)
        .max(4);

    // Print header
    println!(
        "{:<id_w$}  {:<name_w$}  {:<scope_w$}  {:<type_w$}  URI PREFIX",
        "ID",
        "NAME",
        "SCOPE",
        "TYPE",
        id_w = id_width,
        name_w = name_width,
        scope_w = scope_width,
        type_w = type_width,
    );

    println!(
        "{:-<id_w$}  {:-<name_w$}  {:-<scope_w$}  {:-<type_w$}  {:-<30}",
        "",
        "",
        "",
        "",
        "",
        id_w = id_width,
        name_w = name_width,
        scope_w = scope_width,
        type_w = type_width,
    );

    // Print rows
    for item in &resp.items {
        let name_display = truncate_column(&item.name, name_width);
        let scope_display = truncate_column(&item.scope, scope_width);

        println!(
            "{:<id_w$}  {:<name_w$}  {:<scope_w$}  {:<type_w$}  {}",
            item.id,
            name_display,
            scope_display,
            item.cipher_type,
            item.uri_prefix,
            id_w = id_width,
            name_w = name_width,
            scope_w = scope_width,
            type_w = type_width,
        );
    }

    let unique_items = resp
        .items
        .iter()
        .map(|item| &item.id)
        .collect::<HashSet<_>>()
        .len();
    let entry_label = if resp.total == 1 { "entry" } else { "entries" };
    let item_label = if unique_items == 1 { "item" } else { "items" };
    println!(
        "\nTotal: {} {entry_label} ({} unique {item_label})",
        resp.total, unique_items
    );
    Ok(())
}

fn truncate_column(value: &str, width: usize) -> String {
    if value.chars().count() > width {
        let prefix: String = value.chars().take(width.saturating_sub(3)).collect();
        format!("{prefix}...")
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::truncate_column;

    #[test]
    fn preserves_values_within_character_limit() {
        for value in [
            "",
            "GitHub",
            "サンプルサービス - アカウント管理ページ",
            "🔑🔒😀",
        ] {
            assert_eq!(truncate_column(value, 40), value);
            assert_eq!(truncate_column(value, value.chars().count()), value);
        }
    }

    #[test]
    fn truncates_at_character_boundaries() {
        for (value, width, expected) in [
            ("abcdefghij", 8, "abcde..."),
            (
                "サンプルサービス - アカウント管理ページ",
                15,
                "サンプルサービス - ア...",
            ),
            ("personal/日本語の長いフォルダー", 15, "personal/日本語..."),
            ("🔑🔒😀🔑🔒😀", 5, "🔑🔒..."),
        ] {
            let result = truncate_column(value, width);
            assert_eq!(result, expected);
            assert_eq!(result.chars().count(), width);
        }
    }
}
