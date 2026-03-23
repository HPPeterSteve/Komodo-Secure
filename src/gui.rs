use eframe::egui;
use sysinfo::System;
use std::path::PathBuf;
use crate::vault;
use crate::crypto;

#[derive(PartialEq)]
enum Tab {
    Main,
    Resources,
    Files,
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
            logs: vec!["Komodo-Secure GUI Iniciada - Todas as funções CLI integradas".to_string()],
            files_in_dir: Vec::new(),
            current_dir: ".".to_string(),
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
}

impl eframe::App for KomodoApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.refresh_system();
        
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🛡️ Komodo-Secure");
            
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.tab, Tab::Main, "Segurança (CLI)");
                ui.selectable_value(&mut self.tab, Tab::Resources, "Monitor de Recursos");
                ui.selectable_value(&mut self.tab, Tab::Files, "Explorador de Arquivos");
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
                                    ui.text_edit_singleline(&mut self.vault_path);
                                });
                                ui.horizontal(|ui| {
                                    ui.label("Arquivo/Origem:");
                                    ui.text_edit_singleline(&mut self.file_path);
                                });
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
                                    if ui.button("Criar Cofre").on_hover_text("create-vault").clicked() {
                                        if !self.vault_path.is_empty() {
                                            vault::create(&self.vault_path);
                                            self.add_log(&format!("Cofre criado em: {}", self.vault_path));
                                        }
                                    }
                                    if ui.button("Adicionar Arquivo").on_hover_text("add-file").clicked() {
                                        if !self.vault_path.is_empty() && !self.file_path.is_empty() {
                                            match vault::add_file(&self.vault_path, &self.file_path) {
                                                Ok(_) => self.add_log("Arquivo adicionado ao cofre"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Remover Arquivo").on_hover_text("remove-file").clicked() {
                                        if !self.vault_path.is_empty() && !self.file_path.is_empty() {
                                            match vault::remove_file(&self.vault_path, &self.file_path) {
                                                Ok(_) => self.add_log("Arquivo removido do cofre"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Status do Cofre").on_hover_text("status").clicked() {
                                        if !self.vault_path.is_empty() {
                                            match vault::get_vault_status(&self.vault_path) {
                                                Ok(_) => self.add_log("Status verificado (veja terminal para detalhes)"),
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
                                    if ui.button("Criptografar").on_hover_text("encrypt").clicked() {
                                        if !self.file_path.is_empty() && !self.password.is_empty() {
                                            match crypto::encrypt_file(&PathBuf::from(&self.file_path), &self.password) {
                                                Ok(_) => self.add_log("Arquivo criptografado (.enc)"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Descriptografar").on_hover_text("decrypt").clicked() {
                                        if !self.file_path.is_empty() && !self.password.is_empty() {
                                            match crypto::decrypt_file(&PathBuf::from(&self.file_path), &self.password) {
                                                Ok(_) => self.add_log("Arquivo descriptografado (.dec)"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Secure Copy").on_hover_text("secure-copy").clicked() {
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
                                    if ui.button("Isolar Diretório").on_hover_text("isolate-directory").clicked() {
                                        if !self.vault_path.is_empty() {
                                            vault::isolate_directory(&self.vault_path);
                                            self.add_log(&format!("Diretório isolado: {}", self.vault_path));
                                        }
                                    }
                                    if ui.button("Cópia Segura").on_hover_text("safe-copy").clicked() {
                                        if !self.file_path.is_empty() && !self.dest_path.is_empty() {
                                            match vault::safe_copy(&self.file_path, &self.dest_path) {
                                                Ok(_) => self.add_log("Cópia atômica realizada com sucesso"),
                                                Err(e) => self.add_log(&format!("Erro: {}", e)),
                                            }
                                        }
                                    }
                                    if ui.button("Listar Diretório").on_hover_text("read-directory").clicked() {
                                        if !self.vault_path.is_empty() {
                                            let files = vault::read_directory(&self.vault_path);
                                            self.add_log(&format!("Encontrados {} arquivos", files.len()));
                                        }
                                    }
                                });
                            });

                            ui.add_space(20.0);
                            ui.label("Histórico de Ações:");
                            egui::ScrollArea::vertical().max_height(150.0).show(ui, |ui| {
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
                        if self.files_in_dir.is_empty() {
                            self.refresh_files();
                        }
                        for file in &self.files_in_dir {
                            ui.label(format!("📄 {}", file));
                        }
                    });
                }
            }
        });

        ctx.request_repaint();
    }
}
