use windows::Win32::{
    System::Diagnostics::ToolHelp::PROCESS_MEMORY_COUNTERS,
    System::Diagnostics::ToolHelp::K32GetProcessMemoryInfo,
    System::Threading::GetCurrentProcess,
};

fn print_memory_winapi() {
    unsafe {
        let handle = GetCurrentProcess();
        let mut pmc = PROCESS_MEMORY_COUNTERS::default();
        if K32GetProcessMemoryInfo(handle, &mut pmc, std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32).as_bool() {
            println!("Uso de memória (Working Set): {:.2} MB", pmc.WorkingSetSize as f64 / 1024.0 / 1024.0);
            println!("Memória virtual (Pagefile): {:.2} MB", pmc.PagefileUsage as f64 / 1024.0 / 1024.0);
        } else {
            println!("Falha ao obter memória do processo");
        }
    }
}