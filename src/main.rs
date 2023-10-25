use getopts::Options;
use pcap::Capture;
use std::env;
use std::error::Error;
use std::path::Path;
use wasmedge_sdk::{
    config::{CommonConfigOptions, ConfigBuilder, HostRegistrationConfigOptions},
    dock::{Param, VmDock},
    plugin::PluginManager,
    Module, VmBuilder,
};

struct Opts {
    wasm_file_path: String,
    filter: String,
    interface: String,
    is_promiscuous: bool,
    enable_tls_plugin: bool,
}

fn parse_opts() -> Result<Opts, Box<dyn Error>> {
    const FILTER_LONG_OPT_NAME: &str = "filter";
    const INTERFACE_LONG_OPT_NAME: &str = "interface";
    const PROMISCUOUS_LONG_OPT_NAME: &str = "promiscuous";
    const HELP_LONG_OPT_NAME: &str = "help";
    const WASM_FILE_LONG_OPT_NAME: &str = "wasm-file";
    const TLS_LONG_OPT_NAME: &str = "tls-enable";

    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();

    let mut opts = Options::new();
    opts.optopt(
        "w",
        WASM_FILE_LONG_OPT_NAME,
        "file path to the wasm file",
        "/path/to/app.wasm",
    );
    opts.optopt(
        "i",
        INTERFACE_LONG_OPT_NAME,
        "network interface name",
        "INTERFACE",
    );
    opts.optopt(
        "f",
        FILTER_LONG_OPT_NAME,
        "packet capture filter condition; ref: https://biot.com/capstats/bpf.html",
        "FILTER",
    );
    opts.optflag(
        "",
        PROMISCUOUS_LONG_OPT_NAME,
        "capture packets as promiscuous mode",
    );
    opts.optflag(
        "",
        TLS_LONG_OPT_NAME,
        "enable WasmEdge TLS plugin; WasmEdge rustls plugin must be installed",
    );
    opts.optflag("h", HELP_LONG_OPT_NAME, "print this help menu");
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(f) => return Err(f.into()),
    };

    if matches.opt_present(HELP_LONG_OPT_NAME) {
        let brief = format!("Usage: {} [options]", program);
        print!("{}", opts.usage(&brief));
        return Err("TODO: usage shown".into());
    }

    let wasm_file_path = match matches.opt_str(WASM_FILE_LONG_OPT_NAME) {
        Some(warm_file_path) => warm_file_path,
        None => {
            return Err(format!(
                "--{} option is mandatory but the value is missing",
                WASM_FILE_LONG_OPT_NAME
            )
            .into())
        }
    };

    let filter = match matches.opt_str(FILTER_LONG_OPT_NAME) {
        Some(filter) => filter,
        None => {
            return Err(format!(
                "--{} option is mandatory but the value is missing",
                FILTER_LONG_OPT_NAME
            )
            .into())
        }
    };

    let interface = match matches.opt_str(INTERFACE_LONG_OPT_NAME) {
        Some(interface) => interface,
        None => {
            return Err(format!(
                "--{} option is mandatory but the value is missing",
                INTERFACE_LONG_OPT_NAME
            )
            .into())
        }
    };

    Ok(Opts {
        wasm_file_path,
        filter,
        interface,
        is_promiscuous: matches.opt_present(PROMISCUOUS_LONG_OPT_NAME),
        enable_tls_plugin: matches.opt_present(TLS_LONG_OPT_NAME),
    })
}

fn init_wasm_vm(wasm_filepath: &Path, enable_tls_plugin: bool) -> Result<VmDock, Box<dyn Error>> {
    PluginManager::load(None)?;

    let module = Module::from_file(None, wasm_filepath)?;

    let config = ConfigBuilder::new(CommonConfigOptions::default())
        .with_host_registration_config(HostRegistrationConfigOptions::default().wasi(true))
        .build()?;

    if !config.wasi_enabled() {
        return Err("wasi is unable on WasmEdge configuration".into());
    }

    let mut vm_builder = VmBuilder::new().with_config(config);
    if enable_tls_plugin {
        vm_builder = vm_builder.with_plugin("rustls", "rustls_client");
    }

    Ok(VmDock::new(
        vm_builder.build()?.register_module(None, module)?,
    ))
}

fn main() -> Result<(), Box<dyn Error>> {
    let opts = match parse_opts() {
        Ok(opts) => opts,
        Err(e) => {
            return Err(e);
        }
    };

    let mut cap = Capture::from_device(opts.interface.as_str())?
        .immediate_mode(true)
        .promisc(opts.is_promiscuous)
        .open()?;
    cap.filter(&opts.filter, true)?;

    let vm = init_wasm_vm(Path::new(&opts.wasm_file_path), opts.enable_tls_plugin)?;

    while let Ok(packet) = cap.next_packet() {
        match vm.run_func("run", vec![Param::VecU8(&packet.data.to_vec())])? {
            Ok(_) => {}
            Err(e) => {
                // TODO: don't exit mode
                return Err(e.into());
            }
        };
    }

    Ok(())
}
