// language: Rust, file: crates/core/src/rootkit_hunter.rs, runtime: pure-rust, target: Linux
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelIntegrityReport {
    pub is_clean: bool,
    pub hidden_lkm_modules: Vec<String>,
    pub hidden_pids: Vec<u32>,
    pub timestamp: u64,
    pub formatted_time: String,
    pub summary: String,
}

pub struct RootkitHunter;

impl RootkitHunter {
    /// Detecta módulos de kernel (LKM) furtivos que se desvincularam da lista do `/proc/modules`
    pub fn detect_hidden_lkm() -> Vec<String> {
        let mut loaded_in_proc = HashSet::new();

        if let Ok(proc_modules) = fs::read_to_string("/proc/modules") {
            for line in proc_modules.lines() {
                if let Some(mod_name) = line.split_whitespace().next() {
                    loaded_in_proc.insert(mod_name.replace('-', "_"));
                }
            }
        }

        let mut hidden = Vec::new();
        let sys_modules = Path::new("/sys/module");

        if let Ok(entries) = fs::read_dir(sys_modules) {
            for entry in entries.flatten() {
                let mod_name = entry.file_name().to_string_lossy().to_string();
                let clean_name = mod_name.replace('-', "_");

                // Módulos dinâmicos possuem o arquivo 'initstate' marcado como 'live'
                let initstate_path = entry.path().join("initstate");
                if let Ok(state_str) = fs::read_to_string(initstate_path) {
                    if state_str.trim() == "live" && !loaded_in_proc.contains(&clean_name) {
                        hidden.push(mod_name);
                    }
                }
            }
        }

        hidden
    }

    /// Detecta processos ocultos em Ring 3 via evasão de getdents64 (DKOM Heuristic)
    /// Compara a enumeração do VFS /proc (incluindo threads em /proc/*/task/*) com a resposta direta da syscall kill(pid, 0)
    pub fn detect_hidden_pids() -> Vec<u32> {
        let mut visible_tasks = HashSet::new();

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(name) = entry.file_name().into_string() {
                    if let Ok(pid) = name.parse::<u32>() {
                        visible_tasks.insert(pid);

                        // Coleta todas as threads legítimas daquele processo em /proc/{pid}/task/
                        let task_dir = format!("/proc/{}/task", pid);
                        if let Ok(threads) = fs::read_dir(task_dir) {
                            for t in threads.flatten() {
                                if let Ok(t_name) = t.file_name().into_string() {
                                    if let Ok(tid) = t_name.parse::<u32>() {
                                        visible_tasks.insert(tid);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        let max_pid = Self::get_max_pid();
        let mut hidden = Vec::new();

        for pid in 1..=max_pid {
            let res = unsafe { libc::kill(pid as i32, 0) };
            let err = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);

            // Se a task existe no escalonador do kernel (0) ou recebemos EPERM (processo de outro usuário/root):
            let exists_in_kernel = res == 0 || err == libc::EPERM;

            if exists_in_kernel && !visible_tasks.contains(&pid) {
                hidden.push(pid);
            }
        }

        hidden
    }

    pub fn audit() -> KernelIntegrityReport {
        let hidden_lkm = Self::detect_hidden_lkm();
        let hidden_pids = Self::detect_hidden_pids();
        let is_clean = hidden_lkm.is_empty() && hidden_pids.is_empty();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let hours = (now / 3600) % 24;
        let mins = (now / 60) % 60;
        let secs = now % 60;
        let formatted_time = format!("{:02}:{:02}:{:02}", hours, mins, secs);

        let summary = if is_clean {
            "RING 0 AUDIT // KERNEL LIMPO // ZERO ROOTKITS DETECTADOS".to_string()
        } else {
            format!(
                "ALERTA CRÍTICO // {} MÓDULOS OCULTOS // {} PROCESSOS FANTASMAS (DKOM)",
                hidden_lkm.len(),
                hidden_pids.len()
            )
        };

        KernelIntegrityReport {
            is_clean,
            hidden_lkm_modules: hidden_lkm,
            hidden_pids,
            timestamp: now,
            formatted_time,
            summary,
        }
    }

    fn get_max_pid() -> u32 {
        if let Ok(last) = fs::read_to_string("/proc/sys/kernel/ns_last_pid") {
            if let Ok(n) = last.trim().parse::<u32>() {
                return (n + 200).min(4194304);
            }
        }
        65535
    }
}
