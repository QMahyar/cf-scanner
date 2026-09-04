use super::super::{Cli, Command, ModeArg, PresetArg, ProbeArg, ScanArgs};
use super::{build_scan_config, cap_warning};
use cf_scanner::api;
use cf_scanner::api::types::{
    CdnPreset, DEFAULT_CONCURRENCY, DEFAULT_PORT, Mode, Port, ProbeMode, ScanTarget, StopCondition,
};
use cf_scanner::export::ExportFormatArg;
use clap::Parser;

fn args() -> ScanArgs {
    ScanArgs {
        mode: ModeArg::Cdn,
        preset: None,
        count: None,
        target: 20,
        cap: None,
        ports: None,
        concurrency: DEFAULT_CONCURRENCY,
        timeout_ms: 3000,
        exclude: vec![],
        custom_cidrs: vec![],
        colo: vec![],
        ipv6: false,
        phase2_configs: vec![],
        phase2_only: false,
        phase2_fragment: None,
        phase2_custom: None,
        phase2_snis: vec![],
        phase2_probe_urls: vec![],
        phase2_concurrency: None,
        warp_probes: None,
        warp_endpoints: vec![],
        warp_verify: false,
        warp_wgconf_file: None,
        seed: None,
        export: None,
        export_format: ExportFormatArg::Csv,
        loss_threshold: None,
        min_latency: None,
        idle_hold_ms: 0,
        probe: ProbeArg::Tls,
        http_status_code: None,
        speed_test: false,
        min_speed: None,
        neighbor_scan: 0,
        enrich_asn: false,
    }
}

#[test]
fn defaults_to_quick_preset_and_port_443() {
    let cfg = build_scan_config(&args()).unwrap();
    assert_eq!(cfg.target, ScanTarget::Preset(CdnPreset::Quick));
    assert_eq!(cfg.ports, vec![Port::new(DEFAULT_PORT)]);
    assert_eq!(
        cfg.stop,
        StopCondition {
            found: 20,
            cap: None
        }
    );
}

#[test]
fn count_target_sets_exact_count() {
    let mut a = args();
    a.count = Some(350);
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.target, ScanTarget::Count(350));
}

#[test]
fn warp_defaults_to_the_full_pool() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(
        cfg.target,
        ScanTarget::Count(cf_scanner::warp::bundled_pool().host_count() as u32),
        "WARP without --count must scan the whole bundled pool"
    );
}

#[test]
fn colo_flag_builds_the_filter_normalized() {
    let argv = [
        "cf-scanner",
        "scan",
        "--colo",
        " hkg ,Nrt ",
        "--count",
        "10",
    ];
    let scan_args = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&scan_args).unwrap();
    assert_eq!(
        cfg.colo_filter,
        vec!["HKG".to_owned(), "NRT".to_owned()],
        "colo codes must trim and normalize to uppercase"
    );
    assert_eq!(
        build_scan_config(&args()).unwrap().colo_filter,
        Vec::<String>::new()
    );
}

#[test]
fn colo_rejects_bad_codes() {
    let mut a = args();
    a.colo = vec!["HKG".to_owned(), "x1".to_owned()];
    let err = build_scan_config(&a).unwrap_err();
    assert!(
        err.to_string().contains("--colo") || err.to_string().contains("colo"),
        "{err:#}"
    );
    let mut a = args();
    a.colo = vec!["TOOLONGCODE".to_owned()];
    assert!(build_scan_config(&a).is_err());
    let mut a = args();
    a.colo = vec!["".to_owned()];
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--colo"), "{err:#}");
}

#[test]
fn warp_mode_rejects_colo_with_a_flag_named_error() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.colo = vec!["HKG".to_owned()];
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--colo"), "{err:#}");
}

#[test]
fn colo_flag_round_trips_validate() {
    let argv = ["cf-scanner", "scan", "--colo", "HKG,NRT", "--count", "10"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&a).unwrap();
    cfg.validate()
        .expect("a CLI-built colo filter must pass ScanConfig::validate");
}

#[test]
fn phase2_only_is_rejected_in_one_shot_scans() {
    let mut a = args();
    a.phase2_only = true;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--phase2-only"), "{err:#}");
}

#[test]
fn phase2_custom_requires_configs_and_custom_fragment() {
    let argv = ["cf-scanner", "scan", "--phase2-custom", "100-200,10-20"];
    assert!(Cli::try_parse_from(argv).is_err());
    let mut a = args();
    a.phase2_configs = vec!["vless://a@1.2.3.4:443".to_owned()];
    a.phase2_custom = Some("100-200,10-20".to_owned());
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--phase2-custom"), "{err:#}");
}

#[test]
fn cap_zero_is_rejected() {
    let mut a = args();
    a.cap = Some(0);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--cap"), "{err:#}");
}

#[test]
fn loss_threshold_and_idle_hold_build_scan_config() {
    let argv = [
        "cf-scanner",
        "scan",
        "--loss-threshold",
        "30",
        "--idle-hold-ms",
        "1500",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.loss_threshold, Some(30));
    assert_eq!(cfg.idle_hold_ms, 1500);
    assert_eq!(
        build_scan_config(&args()).unwrap().loss_threshold,
        None,
        "the loss threshold must default to off"
    );
    assert_eq!(build_scan_config(&args()).unwrap().idle_hold_ms, 0);
}

#[test]
fn loss_threshold_and_idle_hold_out_of_range_are_rejected() {
    let mut a = args();
    a.loss_threshold = Some(101);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--loss-threshold"), "{err:#}");
    let mut a = args();
    a.idle_hold_ms = api::types::MAX_IDLE_HOLD_MS + 1;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--idle-hold-ms"), "{err:#}");
}

#[test]
fn min_latency_builds_scan_config() {
    let argv = ["cf-scanner", "scan", "--min-latency", "250"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.min_latency_ms, Some(250));
    assert_eq!(
        build_scan_config(&args()).unwrap().min_latency_ms,
        None,
        "the latency lower bound must default to off"
    );
}

#[test]
fn min_latency_out_of_range_is_rejected() {
    let mut a = args();
    a.min_latency = Some(0);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--min-latency"), "{err:#}");
    let mut a = args();
    a.min_latency = Some(api::types::MAX_MIN_LATENCY_MS + 1);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--min-latency"), "{err:#}");
}

#[test]
fn neighbor_scan_flag_builds_and_validates() {
    let argv = ["cf-scanner", "scan", "--neighbor-scan", "4"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.neighbor_count, 4);
    assert_eq!(build_scan_config(&args()).unwrap().neighbor_count, 0);
    let mut a = args();
    a.neighbor_scan = api::types::MAX_NEIGHBORS + 1;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--neighbor-scan"), "{err:#}");
}

#[test]
fn warp_mode_rejects_neighbor_scan_with_a_flag_named_error() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.neighbor_scan = 4;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--neighbor-scan"), "{err:#}");
    let mut a = args();
    a.mode = ModeArg::Warp;
    assert!(
        build_scan_config(&a).is_ok(),
        "neighbor_scan=0 must stay legal in WARP mode"
    );
}

#[test]
fn probe_defaults_to_tls_and_parses_all_modes() {
    let cfg = build_scan_config(&args()).unwrap();
    assert_eq!(cfg.probe_mode, ProbeMode::Tls);
    assert_eq!(
        cfg.accepted_http_codes,
        api::types::DEFAULT_ACCEPTED_HTTP_CODES.to_vec()
    );
    let argv = ["cf-scanner", "scan", "--probe", "tcp"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert_eq!(build_scan_config(&a).unwrap().probe_mode, ProbeMode::Tcp);
    let argv = ["cf-scanner", "scan", "--probe", "tls"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert_eq!(build_scan_config(&a).unwrap().probe_mode, ProbeMode::Tls);
    let argv = ["cf-scanner", "scan", "--probe", "http"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert_eq!(build_scan_config(&a).unwrap().probe_mode, ProbeMode::Http);
}

#[test]
fn http_status_code_requires_probe_http() {
    let mut a = args();
    a.http_status_code = Some(vec![200]);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--http-status-code"), "{err:#}");
    a.probe = ProbeArg::Http;
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.accepted_http_codes, vec![200]);
    assert_eq!(cfg.probe_mode, ProbeMode::Http);
}

#[test]
fn http_status_code_parses_comma_delimited_and_validates_range() {
    let argv = [
        "cf-scanner",
        "scan",
        "--probe",
        "http",
        "--http-status-code",
        "200,204",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.accepted_http_codes, vec![200, 204]);
    let argv = [
        "cf-scanner",
        "scan",
        "--probe",
        "http",
        "--http-status-code",
        "99",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--http-status-code"), "{err:#}");
    let argv = [
        "cf-scanner",
        "scan",
        "--probe",
        "http",
        "--http-status-code",
        "600",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert!(build_scan_config(&a).is_err());
}

#[test]
fn probe_flag_is_cdn_only() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.probe = ProbeArg::Http;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--probe"), "{err:#}");
}

#[test]
fn zero_count_and_target_name_the_flag() {
    let mut a = args();
    a.count = Some(0);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--count"), "{err:#}");
    let mut a = args();
    a.target = 0;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--target"), "{err:#}");
}

#[test]
fn warp_mode_rejects_phase2_configs_with_a_flag_named_error() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.phase2_configs = vec!["vless://a@1.2.3.4:443".to_owned()];
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--phase2-configs"), "{err:#}");
}

#[test]
fn warp_mode_rejects_custom_cidrs_with_a_flag_named_error() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.custom_cidrs = vec!["203.0.113.0/24".to_owned()];
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--custom-cidrs"), "{err:#}");
}

#[test]
fn cap_below_target_warns_instead_of_erroring() {
    let mut a = args();
    a.cap = Some(10);
    let warning = cap_warning(&a).unwrap();
    assert!(
        warning.contains("--cap") && warning.contains("--target"),
        "{warning}"
    );
    let mut a = args();
    a.cap = Some(25);
    assert!(cap_warning(&a).is_none());
    assert!(cap_warning(&args()).is_none());
    let cfg = {
        let mut a = args();
        a.cap = Some(10);
        build_scan_config(&a).unwrap()
    };
    assert_eq!(cfg.stop.cap, Some(10));
}

#[test]
fn preset_wins_over_default_when_given() {
    let mut a = args();
    a.preset = Some(PresetArg::Full);
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.target, ScanTarget::Preset(CdnPreset::Full));
}

#[test]
fn explicit_ports_are_used() {
    let mut a = args();
    a.ports = Some(vec![443, 8443]);
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.ports, vec![Port::new(443), Port::new(8443)]);
}

#[test]
fn warp_mode_uses_warp_ports() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.mode, Mode::Warp);
    assert_eq!(cfg.ports.as_slice(), api::types::DEFAULT_WARP_PORTS);
}

#[test]
fn parses_comma_delimited_flags() {
    let argv = [
        "cf-scanner",
        "scan",
        "--mode",
        "warp",
        "--ports",
        "2408,500",
        "--exclude",
        "1.2.3.0/24,2.3.4.0/24",
        "--warp-endpoints",
        "203.0.113.1,203.0.113.2:2408",
        "--target",
        "5",
        "--cap",
        "100",
        "--seed",
        "42",
    ];
    let scan_args = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert_eq!(scan_args.mode, ModeArg::Warp);
    assert_eq!(scan_args.ports, Some(vec![2408, 500]));
    assert_eq!(scan_args.seed, Some(42));
    let cfg = build_scan_config(&scan_args).unwrap();
    assert_eq!(
        cfg.exclude,
        vec!["1.2.3.0/24".to_owned(), "2.3.4.0/24".to_owned()]
    );
    assert_eq!(cfg.custom_cidrs, Vec::<String>::new());
    assert_eq!(
        cfg.stop,
        StopCondition {
            found: 5,
            cap: Some(100)
        }
    );
    let warp = cfg.warp.as_ref().unwrap();
    assert_eq!(warp.probes_per_endpoint, 3);
    assert_eq!(
        warp.custom_endpoints,
        vec!["203.0.113.1".to_owned(), "203.0.113.2:2408".to_owned()]
    );
}

#[test]
fn warp_flags_build_a_warp_config() {
    let argv = [
        "cf-scanner",
        "scan",
        "--mode",
        "warp",
        "--count",
        "50",
        "--warp-probes",
        "5",
        "--warp-endpoints",
        "8.8.8.8,1.1.1.1:500",
    ];
    let scan_args = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&scan_args).unwrap();
    let warp = cfg.warp.unwrap();
    assert_eq!(warp.probes_per_endpoint, 5);
    assert_eq!(
        warp.custom_endpoints,
        vec!["8.8.8.8".to_owned(), "1.1.1.1:500".to_owned()]
    );
    assert!(cfg.phase2.is_none());
}

#[test]
fn warp_mode_rejects_preset_and_cdn_rejects_warp_endpoints() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.preset = Some(PresetArg::Quick);
    assert!(build_scan_config(&a).is_err());
    let mut a = args();
    a.warp_endpoints = vec!["8.8.8.8".to_owned()];
    assert!(build_scan_config(&a).is_err());
    let mut a = args();
    a.warp_verify = true;
    a.warp_wgconf_file = Some("tests/fixtures/warp-wgconf.txt".to_owned());
    assert!(build_scan_config(&a).is_err(), "cdn must reject warp flags");
}

#[test]
fn ipv6_flag_enables_v6_ranges() {
    let argv = ["cf-scanner", "scan", "--ipv6"];
    let scan_args = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert!(scan_args.ipv6);
    let cfg = build_scan_config(&scan_args).unwrap();
    assert!(cfg.include_v6);
    assert!(!build_scan_config(&args()).unwrap().include_v6);
}

#[test]
fn warp_mode_rejects_ipv6_flag() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.ipv6 = true;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("CDN-only"), "{err:#}");
}

#[test]
fn warp_verify_loads_the_wgconf_file() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.warp_verify = true;
    a.warp_wgconf_file = Some("tests/fixtures/warp-wgconf.txt".to_owned());
    let cfg = build_scan_config(&a).unwrap();
    let warp = cfg.warp.unwrap();
    assert!(warp.verify_with_wgconf);
    let wg = warp.wgconf.unwrap();
    assert!(wg.contains("[Interface]"));
    assert!(wg.contains("PrivateKey"));
}

#[test]
fn invalid_config_is_rejected() {
    let mut a = args();
    a.concurrency = 0;
    assert!(build_scan_config(&a).is_err());
    let mut a = args();
    a.ports = Some(vec![0]);
    assert!(build_scan_config(&a).is_err());
    let mut a = args();
    a.count = Some(0);
    assert!(build_scan_config(&a).is_err());
    let mut a = args();
    a.custom_cidrs = vec!["garbage".to_owned()];
    assert!(build_scan_config(&a).is_err());
}

#[test]
fn phase2_flags_build_a_phase2_config() {
    let argv = [
        "cf-scanner",
        "scan",
        "--phase2-configs",
        "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeffff0000@1.2.3.4:443,https://sub.example.com/x",
        "--phase2-fragment",
        "heavy",
        "--phase2-snis",
        "a.com,b.com",
        "--phase2-concurrency",
        "4",
    ];
    let scan_args = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let cfg = build_scan_config(&scan_args).unwrap();
    let p2 = cfg.phase2.unwrap();
    assert_eq!(p2.configs.len(), 2);
    assert_eq!(p2.fragment, api::types::FragmentPreset::Heavy);
    assert_eq!(p2.snis, vec!["a.com".to_owned(), "b.com".to_owned()]);
    assert_eq!(p2.concurrency, 4);
    assert_eq!(p2.probe_url, api::types::DEFAULT_PROBE_URL);
}

#[test]
fn phase2_absent_by_default_and_custom_requires_values() {
    let cfg = build_scan_config(&args()).unwrap();
    assert!(cfg.phase2.is_none());
    let argv = [
        "cf-scanner",
        "scan",
        "--phase2-configs",
        "vless://a@1.2.3.4:443",
        "--phase2-fragment",
        "custom",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    assert!(build_scan_config(&a).is_err());
}

#[test]
fn phase2_custom_fragment_values_parse() {
    let argv = [
        "cf-scanner",
        "scan",
        "--phase2-configs",
        "vless://a@1.2.3.4:443",
        "--phase2-fragment",
        "custom",
        "--phase2-custom",
        "100-200,10-20",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let p2 = build_scan_config(&a).unwrap().phase2.unwrap();
    assert_eq!(p2.fragment, api::types::FragmentPreset::Custom);
    let c = p2.custom_fragment.unwrap();
    assert_eq!(c.length, "100-200");
    assert_eq!(c.interval, "10-20");
}

#[test]
fn phase2_probe_urls_flag_builds_the_multi_url_list() {
    let argv = [
        "cf-scanner",
        "scan",
        "--phase2-configs",
        "vless://a@1.2.3.4:443",
        "--phase2-probe-urls",
        "https://cp.cloudflare.com/,https://www.cloudflare.com/",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let p2 = build_scan_config(&a).unwrap().phase2.unwrap();
    assert_eq!(
        p2.probe_urls,
        vec![
            "https://cp.cloudflare.com/".to_owned(),
            "https://www.cloudflare.com/".to_owned()
        ]
    );
    let argv = [
        "cf-scanner",
        "scan",
        "--phase2-configs",
        "vless://a@1.2.3.4:443",
        "--phase2-probe-url",
        "https://example.com/check",
    ];
    assert!(
        Cli::try_parse_from(argv).is_err(),
        "the removed singular --phase2-probe-url must fail loudly, not silently no-op"
    );
    let argv = [
        "cf-scanner",
        "scan",
        "--phase2-configs",
        "vless://a@1.2.3.4:443",
        "--phase2-probe-urls",
        "https://a.example/",
        "--phase2-probe-urls",
        "https://b.example/",
    ];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let p2 = build_scan_config(&a).unwrap().phase2.unwrap();
    assert_eq!(
        p2.probe_urls,
        vec![
            "https://a.example/".to_owned(),
            "https://b.example/".to_owned()
        ]
    );
}

#[test]
fn speed_test_requires_phase2_configs_and_is_opt_in() {
    assert!(
        Cli::try_parse_from(["cf-scanner", "scan", "--speed-test"]).is_err(),
        "--speed-test without --phase2-configs must fail at parse level"
    );
    let cfg = build_scan_config(&args()).unwrap();
    assert!(!cfg.speed_test, "the speed test is strictly opt-in");
    assert_eq!(cfg.min_speed_mbps, None);
    let mut a = args();
    a.phase2_configs = vec!["vless://a@1.2.3.4:443".to_owned()];
    a.speed_test = true;
    let cfg = build_scan_config(&a).unwrap();
    assert!(cfg.speed_test);
    assert_eq!(cfg.min_speed_mbps, None);
}

#[test]
fn min_speed_requires_speed_test() {
    assert!(
        Cli::try_parse_from(["cf-scanner", "scan", "--min-speed", "5"]).is_err(),
        "--min-speed without --speed-test must fail at parse level"
    );
    let mut a = args();
    a.phase2_configs = vec!["vless://a@1.2.3.4:443".to_owned()];
    a.min_speed = Some(5.0);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--speed-test"), "{err:#}");
    let mut a = args();
    a.phase2_configs = vec!["vless://a@1.2.3.4:443".to_owned()];
    a.speed_test = true;
    a.min_speed = Some(2.5);
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.min_speed_mbps, Some(2.5));
}

#[test]
fn min_speed_zero_is_rejected_with_a_flag_named_error() {
    let mut a = args();
    a.speed_test = true;
    a.min_speed = Some(0.0);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--min-speed"), "{err:#}");
}

#[test]
fn warp_mode_rejects_speed_test() {
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.speed_test = true;
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--speed-test"), "{err:#}");
}

#[test]
fn cdn_mode_rejects_explicit_warp_probes() {
    let mut a = args();
    a.warp_probes = Some(5);
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--warp-probes"), "{err:#}");
    let mut a = args();
    a.warp_probes = Some(3);
    let err = build_scan_config(&a).unwrap_err();
    assert!(
        err.to_string().contains("--warp-probes"),
        "even the default value must not silently no-op: {err:#}"
    );
    let mut a = args();
    a.mode = ModeArg::Warp;
    a.warp_probes = Some(5);
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.warp.unwrap().probes_per_endpoint, 5);
    let mut a = args();
    a.mode = ModeArg::Warp;
    let cfg = build_scan_config(&a).unwrap();
    assert_eq!(cfg.warp.unwrap().probes_per_endpoint, 3);
}

#[test]
fn cdn_mode_rejects_warp_probes_at_cli_parse_level() {
    let argv = ["cf-scanner", "scan", "--warp-probes", "5"];
    let a = match Cli::try_parse_from(argv).unwrap().command {
        Command::Scan { args } => *args,
        _ => unreachable!(),
    };
    let err = build_scan_config(&a).unwrap_err();
    assert!(err.to_string().contains("--warp-probes"), "{err:#}");
}
