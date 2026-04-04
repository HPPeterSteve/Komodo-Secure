use eframe::egui;
use sysinfo::System;
use std::path::PathBuf;
use crate::vault;
use crate::crypto;
use crate::path_assistant;
use crate::cli;
use crate::log;

#[derive(PartialEq)]
enum Tab {
    Main,
    Resources,
    Files,
    Help,
}

pub struct KomodoApp {
    tab: Tab,
    system: System,
    vault_path: String,
    file_path: String,
    dest_path: String,
    password: String,
    logs: Vec<String>,
    files_in_dir: Vec<String>,
    current_dir: String,
    path_suggestions: Vec<PathBuf>,
    faq_answer: String,
}

impl Default for KomodoApp {
    fn default() -> Self {
        let mut system = System::new_all();
        system.refresh_all();
        Self {
            tab: Tab::Main,
            system,
            vault_path: String::new(),
            file_path: String::new(),
            dest_path: String::new(),
            password: String::new(),
            logs: vec!["Komodo-Secure GUI Iniciada - Integração Total Ativa".to_string()],
            files_in_dir: Vec::new(),
            current_dir: ".".to_string(),
            path_suggestions: Vec::new(),
            faq_answer: "Escolha uma pergunta na aba Ajuda para ver a resposta.".to_string(),
        }
    }
}

impl KomodoApp {
    fn refresh_system(&mut self) {
        self.system.refresh_cpu_all();
        self.system.refresh_memory();
    }

    fn refresh_files(&mut self) {
        if let Ok(entries) = std::fs::read_dir(&self.current_dir) {
            self.files_in_dir = entries
                .filter_map(|e| e.ok())
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect();
        }
    }

    fn add_log(&mut self, msg: &str) {
        self.logs.push(msg.to_string());
        if self.logs.len() > 50 {
            self.logs.remove(0);
        }
    }

    fn check_path_suggestions(&mut self, path: &str, is_dir: bool) {
        if path.is_empty() {
            self.path_suggestions.clear();
            return;
        }
        
        let p = std::path::Path::new(path);
        if !p.exists() {
            let parent = p.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(std::path::Path::new("."));
            let mut suggestions = Vec::new();

            if let Ok(entries) = std::fs::read_dir(parent) {
                if let Some(target_name) = p.file_name().and_then(|n| n.to_str()) {
                    for entry in entries.flatten() {
                        let entry_path = entry.path();
                        if is_dir && !entry_path.is_dir() { continue; }
                        if !is_dir && !entry_path.is_file() { continue; }

                        if let Some(name) = entry_path.file_name().and_then(|n| n.to_str()) {
                            if path_assistant::get_valid_path(name, is_dir).is_some() || name.contains(target_name) {
                                suggestions.push(entry_path);
                            }
                        }
                    }
                }
            }
            self.path_suggestions = suggestions;
        } else {
            self.path_suggestions.clear();
        }
    }
}

impl eframe::App for KomodoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.refresh_system();
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🛡️ Komodo-Secure");
            
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Main, "Segurança");
                ui.selectable_value(&mut self.tab, Tab::Resources, "Monitor");
                ui.selectable_value(&mut self.tab, Tab::Files, "Arquivos");
                ui.selectable_value(&mut self.tab, Tab::Help, "Ajuda & FAQ");
            });

            ui.separator();

            match self.tab {
                Tab::Main => {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.vertical(|ui| {
                            ui.group(|ui| {
                                ui.label("Configurações de Caminho:");
                                ui.horizontal(|ui| {
                                    ui.label("Cofre/Diretório:");
                                    let vault_path_clone = self.vault_path.clone();
                                    if ui.text_edit_singleline(&mut self.vault_path).changed() {
                                        self.check_path_suggestions(&vault_path_clone, true);
                                    }
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Arquivo/Origem:");
                                    let file_path_clone = self.file_path.clone();
                                    if ui.text_edit_singleline(&mut self.file_path).changed() {
                                        self.check_path_suggestions(&file_path_clone, false);
                                    }
                                });
                                
                                if !self.path_suggestions.is_empty() {
                                    ui.colored_label(egui::Color32::YELLOW, "Sugestões (Levenshtein):");
                                    let mut selected_suggestion = None;
                                    for sug in self.path_suggestions.iter().take(3) {
                                        if ui.button(format!("Usar: {}", sug.display())).clicked() {
                                            selected_suggestion = Some(sug.to_string_lossy().to_string());
                                        }
                                    }
                                    if let Some(sug_str) = selected_suggestion {
                                        self.file_path = sug_str;
                                        self.path_suggestions.clear();
                                    }
                                }

                                ui.horizontal(|ui| {
                                    ui.label("Destino (Cópia):");
                                    ui.text_edit_singleline(&mut self.dest_path);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Senha:");
                                    ui.text_edit_singleline(&mut self.password);
                                });
                            });

                            ui.add_space(10.0);

                            ui.group(|ui| {
                                ui.label("Operações de Cofre:");
                                ui.horizontal_wrapped(|ui| {
                                    if ui.button("Criar Cofre").clicked() {
                                        if !self.vault_path.is_empty() {
                                            vault::create(&self.vault_path);
                                            self.add_log(&format!("Cofre criado em: {}", self.vault_path));
                                        } else {
                                            log::warn("Caminho do cofre vazio!");
                                        }
                                    }
                                    if ui.button("Adicionar Arquivo").clicked() {
                                        if !self.vault_path.is_empty() && !self.file_path.is_empty() {
                                            match vault::add_file(&self.vault_path, &self.file_path) {
                                                Ok(_) => self.add_log("Arquivo adicionado ao cofre"),
                                                Err(e) => {
                                                    log::error(&format!("Erro ao adicionar: {}", e));
                                                    self.add_log(&format!("Erro: {}", e));
                                                }
                                            }
                                        }
                                    }
                                    if ui.button("Remover Arquivo").clicked() {
                                        if !self.vault_path.is_empty() && !self.file_path.is_empty() {
                                            match vault::remove_file(&self.vault_path, &self.file_path) {
                                                Ok(_) => self.add_log("Arquivo removido do cofre"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Status do Cofre").clicked() {
                                        if !self.vault_path.is_empty() {
                                            match vault::get_vault_status(&self.vault_path) {
                                                Ok(_) => self.add_log("Status verificado"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                });
                            });

                            ui.add_space(5.0);

                            ui.group(|ui| {
                                ui.label("Criptografia e Proteção:");
                                ui.horizontal_wrapped(|ui| {
                                    if ui.button("Criptografar").clicked() {
                                        if !self.file_path.is_empty() && !self.password.is_empty() {
                                            match crypto::encrypt_file(&PathBuf::from(&self.file_path), &self.password) {
                                                Ok(_) => self.add_log("Arquivo criptografado (.enc)"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Descriptografar").clicked() {
                                        if !self.file_path.is_empty() && !self.password.is_empty() {
                                            match crypto::decrypt_file(&PathBuf::from(&self.file_path), &self.password) {
                                                Ok(_) => self.add_log("Arquivo descriptografado (.dec)"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Secure Copy").clicked() {
                                        if !self.file_path.is_empty() && !self.vault_path.is_empty() && !self.password.is_empty() {
                                            vault::secure_store(&self.file_path, &self.vault_path, &self.password);
                                            self.add_log("Arquivo protegido e movido para o cofre");
                                        }
                                    }
                                });
                            });

                            ui.add_space(5.0);

                            ui.group(|ui| {
                                ui.label("Isolamento e Sistema:");
                                ui.horizontal_wrapped(|ui| {
                                    if ui.button("Isolar Diretório (Sandbox C)").clicked() {
                                        if !self.vault_path.is_empty() {
                                            vault::isolate_directory(&self.vault_path);
                                            self.add_log(&format!("Isolamento Sandbox C aplicado em: {}", self.vault_path));
                                        }
                                    }
                                    if ui.button("Cópia Segura").clicked() {
                                        if !self.file_path.is_empty() && !self.dest_path.is_empty() {
                                            match vault::safe_copy(&self.file_path, &self.dest_path) {
                                                Ok(_) => self.add_log("Cópia atômica realizada"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Liberar Escrita").clicked() {
                                        if !self.file_path.is_empty() {
                                            vault::allow_write(&self.file_path);
                                            self.add_log(&format!("Escrita liberada: {}", self.file_path));
                                        }
                                    }
                                });
                            });

                            ui.add_space(20.0);
                            ui.label("Histórico de Ações:");
                            egui::ScrollArea::vertical().max_height(100.0).show(ui, |ui| {
                                for log in self.logs.iter().rev() {
                                    ui.label(log);
                                }
                            });
                        });
                    });
                }
                Tab::Resources => {
                    ui.heading("Monitor de Sistema");
                    let total_mem = self.system.total_memory() as f32 / 1024.0 / 1024.0 / 1024.0;
                    let used_mem = self.system.used_memory() as f32 / 1024.0 / 1024.0 / 1024.0;
                    ui.label(format!("Memória: {:.2} GB / {:.2} GB", used_mem, total_mem));
                    ui.add(egui::ProgressBar::new(used_mem / total_mem).text("RAM"));
                    ui.add_space(10.0);
                    ui.label("Uso de CPU por Núcleo:");
                    for (i, cpu) in self.system.cpus().iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.label(format!("CPU {}:", i));
                            ui.add(egui::ProgressBar::new(cpu.cpu_usage() / 100.0).text(format!("{:.1}%", cpu.cpu_usage())));
                        });
                    }
                }
                Tab::Files => {
                    ui.heading("Explorador de Arquivos");
                    ui.horizontal(|ui| {
                        ui.label("Diretório:");
                        if ui.text_edit_singleline(&mut self.current_dir).changed() {
                            self.refresh_files();
                        }
                        if ui.button("Atualizar").clicked() {
                            self.refresh_files();
                        }
                    });
                    ui.separator();
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        if self.files_in_dir.is_empty() { self.refresh_files(); }
                        for file in &self.files_in_dir { ui.label(format!("📄 {}", file)); }
                    });
                }
                Tab::Help => {
                    ui.heading("Ajuda & FAQ (Integrado)");
                    ui.label("Clique em uma pergunta para ver a explicação:");
                    ui.add_space(10.0);
                    
                    if ui.button("(1) Como criar um cofre?").clicked() {
                        self.faq_answer = "Para criar um cofre, use o botão 'Criar Cofre' após definir o caminho no campo 'Cofre/Diretório'.".to_string();
                    }
                    if ui.button("(2) Como adicionar um arquivo ao cofre?").clicked() {
                        self.faq_answer = "Defina o caminho do cofre e o caminho do arquivo, então clique em 'Adicionar Arquivo'.".to_string();
                    }
                    if ui.button("(3) Como ler os arquivos dentro do cofre?").clicked() {
                        self.faq_answer = "Use a aba 'Arquivos' ou o botão 'Listar Diretório' na aba Segurança.".to_string();
                    }
                    if ui.button("(4) Como permitir escrita?").clicked() {
                        self.faq_answer = "Selecione o arquivo e clique em 'Liberar Escrita' para remover restrições de somente-leitura.".to_string();
                    }
                    
                    ui.separator();
                    ui.group(|ui| {
                        ui.label(&self.faq_answer);
                    });
                }
            }
        });

        ctx.request_repaint();
    }
}
