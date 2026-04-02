use crate::vault;
use crate::komodo_mb_usage;
use sysinfo::{ Components, Disks, Networks, System };
use std::ffi::{c_char, CString};
use windows::Win32::Security::PSID;

unsafe extern "C" {
    fn setup_app_container(container_name: *const u16, pSid: *mut PSID) -> bool;
    fn try_hard_isolate(executable_path: *const u16) -> bool;
}

fn mb_to_kb_binary(mb: f64) -> f64 {
    mb * 1024.0
}

pub struct SystemOptions {
    pub cpu: bool,
    pub memory: bool,
    pub disks: bool,
    pub networks: bool,
    pub processes: bool,
}
pub fn check_pid(pid: pid) -> bool {
    let mut sys_info = System::new_all();
    sys_info.refresh_all();

    let running = sys_info.processes().contains_key(&pid);
    println!("PID {} is {}", pid, if running { "running" } else { "not running" });

    running
}

pub fn existent_pids(container_name: &str) -> Vec<i32> {
    let mut sys_info = System::new_all();
    sys_info.refresh_all();

    let mut pids = Vec::new();
    for (pid, process) in sys_info.processes() {
        if process.name().to_string_lossy().contains(container_name) {
            pids.push(*pid); // pid é &Pid, desreferenciando
        }
    }
    pid
}

pub fn system_information(options: SystemOptions) {

let mut sys_info = System::new_all();
sys_info.refresh_all();
println!("System Komodo-Secure");
if options.cpu{  // Informações de CPU
    println!("CPU:");{
        for cpu in sys_info.cpus() {
            println!("  - {}: {}% usage", cpu.name(), cpu.cpu_usage());
        }
    }
}
if options.memory{  // Informações de Memória
    println!("Memory:");
    let used_memory_kb = mb_to_kb_binary(sys_info.used_memory() as f64);
    let free_memory_kb = mb_to_kb_binary(sys_info.free_memory() as f64);
    let komodo_memory_checker: fn() = komodo_mb_usage::print_memory_winapi;
    println!("  - Used: {:.2} KB", used_memory_kb);
    println!("  - Free: {:.2} KB", free_memory_kb);
    komodo_memory_checker();

    println!("Meu processo (sandbox) usando:");
    komodo_memory_checker();
}
if options.disks{  // Informações de Discos
    println!("Disks:");
    for disk in sys_info.disks() {
        println!("  - {}: {} GB total, {} GB available", disk.name().to_string_lossy(), disk.total_space() as f64 / 1_073_741_824.0, disk.available_space() as f64 / 1_073_741_824.0);
    }
}
if options.networks{  // Informações de Rede
    println!("Networks:");
    for network in sys_info.networks() {
        println!("  - {}: {} bytes sent, {} bytes received", network.name().to_string_lossy(), network.bytes_sent(), network.bytes_received());

    }
}
if options.processes{  // Informações de Processos
    println!("Processes:");
    for process in sys_info.processes() {
        println!("  - {}: {}% CPU, {} MB memory", process.name(), process.cpu_usage(), process.memory() as f64 / 1024.0);
    }
  }
}