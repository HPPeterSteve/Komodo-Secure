use std::path::{Path, PathBuf};
use std::fs;
use colored::*;
use inquire::Select;

/// Calcula a distância de Levenshtein entre duas strings para fuzzy matching.
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();
    let m = s1_chars.len();
    let n = s2_chars.len();
    let mut dp = vec![vec![0; n + 1]; m + 1];

    for i in 0..=m { dp[i][0] = i; }
    for j in 0..=n { dp[0][j] = j; }

    for i in 1..=m {
        for j in 1..=n {
            if s1_chars[i - 1] == s2_chars[j - 1] {
                dp[i][j] = dp[i - 1][j - 1];
            } else {
                dp[i][j] = 1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1]);
            }
        }
    }
    dp[m][n]
}

/// Tenta encontrar um caminho similar se o original não existir.
pub fn get_valid_path(input: &str, is_dir: bool) -> Option<PathBuf> {
    let path = PathBuf::from(input);
    
    if path.exists() {
        return Some(path);
    }

    println!("{}", format!("⚠ O caminho '{}' não foi encontrado.", input).yellow());

    // Buscar sugestões no diretório pai ou atual
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    let mut suggestions = Vec::new();

    if let Ok(entries) = fs::read_dir(parent) {
        let target_name = path.file_name()?.to_str()?;
        
        for entry in entries.flatten() {
            let entry_path = entry.path();
            if is_dir && !entry_path.is_dir() { continue; }
            if !is_dir && !entry_path.is_file() { continue; }

            if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                let dist = levenshtein_distance(target_name, name);
                if dist <= 3 || name.contains(target_name) || target_name.contains(name) {
                    suggestions.push(entry_path);
                }
            }
        }
    }

    if suggestions.is_empty() {
        println!("{}", "✖ Nenhuma sugestão encontrada.".red());
        return None;
    }

    // Se houver apenas uma sugestão muito próxima, perguntar
    if suggestions.len() == 1 {
        let sug = &suggestions[0];
        let prompt = format!("Você quis dizer '{}'?", sug.display());
        let options = vec!["Sim", "Não"];
        let ans = Select::new(&prompt, options).prompt().ok()?;
        
        if ans == "Sim" {
            return Some(sug.clone());
        }
    } else {
        // Se houver várias, deixar escolher
        let mut options: Vec<String> = suggestions.iter().map(|p| p.display().to_string()).collect();
        options.push("Nenhum destes".to_string());
        
        let ans = Select::new("Vários caminhos parecidos encontrados. Escolha um:", options).prompt().ok()?;
        if ans != "Nenhum destes" {
            return Some(PathBuf::from(ans));
        }
    }

    None
}

/// Garante que o usuário forneça um caminho válido, seja via argumento ou interativamente.
pub fn ensure_path(provided: Option<&&str>, prompt: &str, is_dir: bool) -> Option<PathBuf> {
    if let Some(path_str) = provided {
        if let Some(valid) = get_valid_path(path_str, is_dir) {
            return Some(valid);
        }
    }

    // Se não foi fornecido ou o fornecido era inválido e recusado, pedir interativamente
    let input = inquire::Text::new(prompt).prompt().ok()?;
    if input.trim().is_empty() { return None; }
    
    get_valid_path(&input, is_dir)
}
