use eframe::egui;
use sysinfo::{System, CpuRefreshKind, MemoryRefreshKind};
use std::path::PathBuf;
use crate::vault;
use crate::crypto;
use crate::log;

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
            password: String::new(),
            logs: vec!["Komodo-Secure GUI Iniciada".to_string()],
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
                ui.selectable_value(&mut self.tab, Tab::Main, "Principal");
                ui.selectable_value(&mut self.tab, Tab::Resources, "Monitor de Recursos");
                ui.selectable_value(&mut self.tab, Tab::Files, "Arquivos");
            });

            ui.separator();

            match self.tab {
                Tab::Main => {
                    ui.vertical(|ui| {
                        ui.label("Caminho do Cofre:");
                        ui.text_edit_singleline(&mut self.vault_path);
                        
                        ui.label("Caminho do Arquivo:");
                        ui.text_edit_singleline(&mut self.file_path);
                        
                        ui.label("Senha (se necessário):");
                        ui.text_edit_singleline(&mut self.password);

                        ui.add_space(10.0);

                        ui.horizontal_wrapped(|ui| {
                            if ui.button("Criar Cofre").clicked() {
                                if !self.vault_path.is_empty() {
                                    vault::create(&self.vault_path);
                                    self.add_log(&format!("Cofre criado em: {}", self.vault_path));
                                }
                            }
                            if ui.button("Adicionar Arquivo").clicked() {
                                if !self.vault_path.is_empty() && !self.file_path.is_empty() {
                                    match vault::add_file(&self.vault_path, &self.file_path) {
                                        Ok(_) => self.add_log("Arquivo adicionado com sucesso"),
                                        Err(e) => self.add_log(&format!("Erro: {}", e)),
                                    }
                                }
                            }
                            if ui.button("Criptografar").clicked() {
                                if !self.file_path.is_empty() && !self.password.is_empty() {
                                    match crypto::encrypt_file(&PathBuf::from(&self.file_path), &self.password) {
                                        Ok(_) => self.add_log("Arquivo criptografado"),
                                        Err(e) => self.add_log(&format!("Erro: {}", e)),
                                    }
                                }
                            }
                            if ui.button("Descriptografar").clicked() {
                                if !self.file_path.is_empty() && !self.password.is_empty() {
                                    match crypto::decrypt_file(&PathBuf::from(&self.file_path), &self.password) {
                                        Ok(_) => self.add_log("Arquivo descriptografado"),
                                        Err(e) => self.add_log(&format!("Erro: {}", e)),
                                    }
                                }
                            }
                            if ui.button("Isolar Diretório").clicked() {
                                if !self.file_path.is_empty() {
                                    vault::isolate_directory(&self.file_path);
                                    self.add_log(&format!("Diretório isolado: {}", self.file_path));
                                }
                            }
                        });

                        ui.add_space(20.0);
                        ui.label("Logs:");
                        egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                            for log in self.logs.iter().rev() {
                                ui.label(log);
                            }
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
                    ui.heading("Listagem de Arquivos");
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

        // Request a repaint to keep the resource monitor updated
        ctx.request_repaint();
    }
}
