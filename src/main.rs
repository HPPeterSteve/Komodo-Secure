mod cli;
mod vault;
mod crypto;
mod log;
mod path_assistant;
mod gui;

use std::{
    error::Error,
    io::{self},
    time::{Duration},
};
use std::ffi::c_char;
use std::path::Path;
use nix::unistd::Uid;
use colored::*;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};

// Declaração FFI para o sandbox.c
unsafe extern "C" {
    pub fn try_hard_isolate(path: *const c_char) -> bool;
}

fn check_root() {
    if !Uid::effective().is_root() {
        eprintln!("{}", "✖ Erro: Este programa deve ser executado como root (sudo).".red());
        eprintln!("{}", "O Komodo-Secure requer privilégios elevados para gerenciar o isolamento do sandbox e namespaces.".yellow());
        std::process::exit(1);
    }
}

struct App {
    input: String,
    messages: Vec<String>,
    history: Vec<String>,
    history_index: usize,
}

impl Default for App {
    fn default() -> App {
        App {
            input: String::new(),
            messages: vec![
                "Bem-vindo ao Komodo-Secure TUI! 🛡️".to_string(),
                "Digite 'help' para ver os comandos disponíveis ou 'exit' para sair.".to_string(),
            ],
            history: Vec::new(),
            history_index: 0,
        }
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    check_root();
    log::info("Aplicação iniciada em modo TUI.");

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and run it
    let app = App::default();
    let res = run_app(&mut terminal, app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("{:?}", err);
    }

    log::info("Aplicação TUI encerrada.");
    Ok(())
}

fn run_app<B: Backend>(terminal: &mut Terminal<B>, mut app: App) -> io::Result<()> {
    loop {
        terminal.draw(|f| ui(f, &app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Enter => {
                        let input = app.input.drain(..).collect::<String>();
                        if input.trim() == "exit" || input.trim() == "quit" {
                            return Ok(());
                        }
                        if !input.trim().is_empty() {
                            app.history.push(input.clone());
                            app.history_index = app.history.len();
                            handle_tui_command(&input, &mut app);
                        }
                    }
                    KeyCode::Char(c) => {
                        app.input.push(c);
                    }
                    KeyCode::Backspace => {
                        app.input.pop();
                    }
                    KeyCode::Up => {
                        if !app.history.is_empty() && app.history_index > 0 {
                            app.history_index -= 1;
                            app.input = app.history[app.history_index].clone();
                        }
                    }
                    KeyCode::Down => {
                        if !app.history.is_empty() && app.history_index < app.history.len() - 1 {
                            app.history_index += 1;
                            app.input = app.history[app.history_index].clone();
                        } else {
                            app.history_index = app.history.len();
                            app.input.clear();
                        }
                    }
                    KeyCode::Esc => {
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    let title = Paragraph::new("Komodo-Secure 🛡️ Terminal User Interface")
        .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let messages: Vec<ListItem> = app
        .messages
        .iter()
        .enumerate()
        .map(|(_, m)| {
            let content = Line::from(Span::raw(m));
            ListItem::new(content)
        })
        .collect();
    let messages = List::new(messages).block(Block::default().borders(Borders::ALL).title("Logs / Saída"));
    f.render_widget(messages, chunks[1]);

    let input = Paragraph::new(app.input.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(Block::default().borders(Borders::ALL).title("Prompt (Digite o comando)"));
    f.render_widget(input, chunks[2]);
}

fn handle_tui_command(input: &str, app: &mut App) {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return;
    }

    app.messages.push(format!("> {}", input));

    match parts[0] {
        "help" => {
            app.messages.push("Comandos disponíveis:".to_string());
            app.messages.push("  create-vault <path>        → cria um cofre".to_string());
            app.messages.push("  add-file <vault> <file>    → adiciona arquivo ao cofre".to_string());
            app.messages.push("  safe-copy <src> <dst>      → copia com segurança".to_string());
            app.messages.push("  allow-write <file>         → libera escrita".to_string());
            app.messages.push("  read-directory <dir>       → lista arquivos".to_string());
            app.messages.push("  isolate-directory <dir>    → isola diretório".to_string());
            app.messages.push("  secure-copy <file> <vault> → protege e armazena".to_string());
            app.messages.push("  encrypt <file>             → criptografa arquivo".to_string());
            app.messages.push("  decrypt <file>             → descriptografa arquivo".to_string());
            app.messages.push("  status <vault>             → status do cofre".to_string());
            app.messages.push("  exit                       → sair".to_string());
        }
        "create-vault" => {
            if let Some(path) = parts.get(1) {
                vault::create(path);
                app.messages.push(format!("✔ Cofre criado em: {}", path));
            } else {
                app.messages.push("Erro: Uso correto: create-vault <path>".to_string());
            }
        }
        "add-file" => {
            if parts.len() >= 3 {
                match vault::add_file(parts[1], parts[2]) {
                    Ok(_) => app.messages.push("✔ Arquivo adicionado ao cofre.".to_string()),
                    Err(e) => app.messages.push(format!("✖ Erro: {}", e)),
                }
            } else {
                app.messages.push("Erro: Uso correto: add-file <vault> <file>".to_string());
            }
        }
        "safe-copy" => {
            if parts.len() >= 3 {
                match vault::safe_copy(parts[1], parts[2]) {
                    Ok(_) => app.messages.push("✔ Cópia segura realizada.".to_string()),
                    Err(e) => app.messages.push(format!("✖ Erro: {}", e)),
                }
            } else {
                app.messages.push("Erro: Uso correto: safe-copy <src> <dst>".to_string());
            }
        }
        "allow-write" => {
            if let Some(path) = parts.get(1) {
                vault::allow_write(path);
                app.messages.push(format!("✔ Escrita liberada para: {}", path));
            } else {
                app.messages.push("Erro: Uso correto: allow-write <file>".to_string());
            }
        }
        "isolate-directory" => {
            if let Some(path) = parts.get(1) {
                vault::isolate_directory(path);
                app.messages.push(format!("✔ Diretório isolado: {}", path));
            } else {
                app.messages.push("Erro: Uso correto: isolate-directory <dir>".to_string());
            }
        }
        "encrypt" => {
            if let Some(path) = parts.get(1) {
                // Para simplificar na TUI, usamos uma senha padrão ou pedimos via log
                // Em uma versão final, poderíamos suspender a TUI para o prompt do inquire
                app.messages.push("Aviso: Use a GUI para operações com senha por enquanto.".to_string());
                match crypto::encrypt_file(Path::new(path), "default_pass") {
                    Ok(_) => app.messages.push(format!("✔ Arquivo {} criptografado.", path)),
                    Err(e) => app.messages.push(format!("✖ Erro: {}", e)),
                }
            } else {
                app.messages.push("Erro: Uso correto: encrypt <file>".to_string());
            }
        }
        "status" => {
            if let Some(path) = parts.get(1) {
                match vault::get_vault_status(path) {
                    Ok(_) => app.messages.push(format!("✔ Status do cofre {} verificado.", path)),
                    Err(e) => app.messages.push(format!("✖ Erro: {}", e)),
                }
            } else {
                app.messages.push("Erro: Uso correto: status <path>".to_string());
            }
        }
        "read-directory" => {
            if let Some(path) = parts.get(1) {
                let files = vault::read_directory(path);
                app.messages.push(format!("Arquivos em {}:", path));
                for f in files {
                    app.messages.push(format!("  - {}", f));
                }
            } else {
                app.messages.push("Erro: Uso correto: read-directory <path>".to_string());
            }
        }
        _ => {
            app.messages.push(format!("Comando desconhecido: {}", parts[0]));
        }
    }
}
