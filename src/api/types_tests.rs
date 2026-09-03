use super::*;

#[test]
fn grammar_fixture_endpoint_and_sni_cases_match_server_rules() {
    let raw = include_str!("../../tests/fixtures/grammar-cases.json");
    let cases: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
    let endpoints = cases.iter().filter(|c| c["kind"] == "endpoint").count();
    let snis = cases.iter().filter(|c| c["kind"] == "sni").count();
    assert!(endpoints >= 10, "fixture must keep endpoint coverage");
    assert!(snis >= 10, "fixture must keep SNI coverage");
    for case in cases.iter().filter(|c| c["kind"] == "endpoint") {
        let input = case["input"].as_str().unwrap();
        let expect_ok = case["expect"] == "ok";
        assert_eq!(
            parse_endpoint(input).is_ok(),
            expect_ok,
            "endpoint {input:?} expected {expect_ok}"
        );
    }
    for case in cases.iter().filter(|c| c["kind"] == "sni") {
        let input = case["input"].as_str().unwrap();
        let expect_ok = case["expect"] == "ok";
        assert_eq!(
            validate_sni(input).is_ok(),
            expect_ok,
            "sni {input:?} expected {expect_ok}"
        );
    }
}

#[test]
fn grammar_fixture_cidr_cases_match_parse_cidr() {
    let raw = include_str!("../../tests/fixtures/grammar-cases.json");
    let cases: Vec<serde_json::Value> = serde_json::from_str(raw).unwrap();
    let checked = cases.iter().filter(|c| c["kind"] == "cidr").count();
    assert!(
        checked >= 15,
        "fixture must keep cidr coverage, got {checked}"
    );
    for case in cases.iter().filter(|c| c["kind"] == "cidr") {
        let input = case["input"].as_str().unwrap();
        let expect_ok = case["expect"] == "ok";
        assert_eq!(
            parse_cidr(input).is_ok(),
            expect_ok,
            "cidr {input:?} expected {expect_ok}"
        );
    }
}

#[test]
fn stop_condition_rejects_unknown_fields() {
    let bad: serde_json::Value = serde_json::json!({"found": 10, "cap": null, "typo": 1});
    assert!(serde_json::from_value::<StopCondition>(bad).is_err());
}

fn valid_config() -> ScanConfig {
    ScanConfig::default()
}

#[test]
fn default_config_is_valid() {
    assert_eq!(valid_config().validate(), Ok(()));
}

#[test]
fn rejects_zero_port() {
    let mut c = valid_config();
    c.ports = vec![Port::new(0)];
    assert_eq!(c.validate(), Err(ConfigError::InvalidPort(0)));
}

#[test]
fn accepts_max_port() {
    let mut c = valid_config();
    c.ports = vec![Port::new(u16::MAX)];
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_empty_ports() {
    let mut c = valid_config();
    c.ports = vec![];
    assert_eq!(c.validate(), Err(ConfigError::InvalidPort(0)));
}

#[test]
fn rejects_zero_count_target() {
    let mut c = valid_config();
    c.target = ScanTarget::Count(0);
    assert_eq!(c.validate(), Err(ConfigError::InvalidCount(0)));
}

#[test]
fn rejects_count_above_cap() {
    let mut c = valid_config();
    c.target = ScanTarget::Count(MAX_SCAN_COUNT + 1);
    assert_eq!(
        c.validate(),
        Err(ConfigError::InvalidCount(MAX_SCAN_COUNT + 1))
    );
}

#[test]
fn accepts_count_at_cap() {
    let mut c = valid_config();
    c.target = ScanTarget::Count(MAX_SCAN_COUNT);
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_v6_slash_zero() {
    let mut c = valid_config();
    c.custom_cidrs = vec!["::/0".to_owned()];
    assert!(matches!(c.validate(), Err(ConfigError::InvalidCidr(_, _))));
}

#[test]
fn accepts_v6_slash_one() {
    let mut c = valid_config();
    c.custom_cidrs = vec!["2001:db8::/1".to_owned()];
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn accepts_preset_target() {
    let mut c = valid_config();
    c.target = ScanTarget::Preset(CdnPreset::Full);
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_zero_found() {
    let mut c = valid_config();
    c.stop = StopCondition {
        found: 0,
        cap: None,
    };
    assert_eq!(c.validate(), Err(ConfigError::InvalidFound(0)));
}

#[test]
fn accepts_cap_below_found() {
    let mut c = valid_config();
    c.stop = StopCondition {
        found: 20,
        cap: Some(10),
    };
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn accepts_cap_equal_to_found() {
    let mut c = valid_config();
    c.stop = StopCondition {
        found: 20,
        cap: Some(20),
    };
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn accepts_unlimited_stop() {
    let mut c = valid_config();
    c.stop = StopCondition::unlimited(50);
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_malformed_cidrs() {
    for bad in [
        "garbage",
        "1.2.3.4",
        "1.2.3.4/33",
        "1.2.3.4/abc",
        "2606:4700::/129",
        "2001:db8::g/64",
    ] {
        let mut c = valid_config();
        c.exclude = vec![bad.to_owned()];
        assert!(c.validate().is_err(), "expected {bad} to be rejected");
    }
}

#[test]
fn accepts_valid_cidrs() {
    for good in [
        "1.2.3.0/24",
        "104.16.0.0/13",
        "172.64.0.0/13",
        "0.0.0.0/0",
        "2606:4700::/32",
        "2400:cb00::/32",
        "::1/128",
    ] {
        let mut c = valid_config();
        c.exclude = vec![good.to_owned()];
        assert_eq!(c.validate(), Ok(()), "expected {good} to be accepted");
    }
}

#[test]
fn include_v6_defaults_to_false() {
    assert!(!ScanConfig::default().include_v6);
    let json = r#"{
        "mode": "Cdn",
        "target": {"Count": 10},
        "ports": [443],
        "stop": {"found": 1, "cap": null},
        "exclude": [],
        "custom_cidrs": [],
        "concurrency": 10,
        "timeout_ms": 3000,
        "phase2": null,
        "warp": null
    }"#;
    let cfg: ScanConfig = serde_json::from_str(json).unwrap();
    assert!(!cfg.include_v6, "omitted field must deserialize as false");
}

#[test]
fn include_v6_round_trips_through_serde() {
    let mut c = valid_config();
    c.include_v6 = true;
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"include_v6\":true"), "{json}");
    let back: ScanConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn rejects_phase2_in_warp_mode() {
    let mut c = valid_config();
    c.mode = Mode::Warp;
    c.phase2 = Some(Phase2Config::default());
    assert_eq!(c.validate(), Err(ConfigError::Phase2WrongMode));
}

#[test]
fn rejects_warp_in_cdn_mode() {
    let mut c = valid_config();
    c.warp = Some(WarpConfig::default());
    assert_eq!(c.validate(), Err(ConfigError::WarpWrongMode));
}

#[test]
fn phase2_requires_configs() {
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config::default());
    assert_eq!(c.validate(), Err(ConfigError::NoConfigs));
}

#[test]
fn rejects_bad_probe_url() {
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        probe_url: "ftp://nope".to_owned(),
        ..Default::default()
    });
    assert_eq!(c.validate(), Err(ConfigError::InvalidProbeUrl));
}

#[test]
fn probe_urls_replace_the_legacy_single_url() {
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        probe_urls: vec!["https://cp.cloudflare.com/".to_owned()],
        ..Default::default()
    });
    assert_eq!(c.validate(), Ok(()));
    let bad = Phase2Config {
        probe_urls: vec!["ftp://nope".to_owned()],
        ..Phase2Config::default()
    };
    assert_eq!(valid_config_with(bad), Err(ConfigError::InvalidProbeUrl));
}

#[test]
fn rejects_too_many_or_oversized_probe_urls() {
    let over = Phase2Config {
        probe_urls: (0..=MAX_PHASE2_ENTRIES)
            .map(|i| format!("https://cp.cloudflare.com/{i}"))
            .collect(),
        ..Phase2Config::default()
    };
    assert_eq!(
        valid_config_with(over),
        Err(ConfigError::TooManyProbeUrls(MAX_PHASE2_ENTRIES + 1))
    );
    let long = Phase2Config {
        probe_urls: vec![format!("https://x/{}", "a".repeat(MAX_PROBE_URL_BYTES))],
        ..Phase2Config::default()
    };
    assert_eq!(
        valid_config_with(long),
        Err(ConfigError::ProbeUrlTooLong(MAX_PROBE_URL_BYTES))
    );
    let at_cap = Phase2Config {
        probe_urls: (0..MAX_PHASE2_ENTRIES)
            .map(|i| format!("https://cp.cloudflare.com/{i}"))
            .collect(),
        ..Phase2Config::default()
    };
    assert_eq!(valid_config_with(at_cap), Ok(()), "8 URLs must be accepted");
}

fn valid_config_with(p2: Phase2Config) -> Result<(), ConfigError> {
    let mut p2 = p2;
    p2.configs = vec!["vless://uuid@example.com:443".to_owned()];
    let mut c = valid_config();
    c.phase2 = Some(p2);
    c.validate()
}

#[test]
fn effective_probe_urls_prefer_the_list_then_the_legacy_url() {
    assert_eq!(
        Phase2Config::default().effective_probe_urls(),
        vec![DEFAULT_PROBE_URL.to_owned()]
    );
    let legacy = Phase2Config {
        probe_url: "https://example.com/one".to_owned(),
        ..Phase2Config::default()
    };
    assert_eq!(
        legacy.effective_probe_urls(),
        vec!["https://example.com/one".to_owned()]
    );
    let listed = Phase2Config {
        probe_urls: vec![
            "https://a.example/".to_owned(),
            "https://b.example/".to_owned(),
        ],
        ..Phase2Config::default()
    };
    assert_eq!(
        listed.effective_probe_urls(),
        vec![
            "https://a.example/".to_owned(),
            "https://b.example/".to_owned()
        ]
    );
}

#[test]
fn probe_urls_round_trip_through_serde() {
    let p2 = Phase2Config {
        probe_urls: vec!["https://a.example/".to_owned()],
        ..Phase2Config::default()
    };
    let json = serde_json::to_string(&p2).unwrap();
    assert!(
        json.contains("\"probe_urls\":[\"https://a.example/\"]"),
        "{json}"
    );
    assert_eq!(serde_json::from_str::<Phase2Config>(&json).unwrap(), p2);
    let legacy = r#"{"configs":["vless://uuid@example.com:443"],"fragment":"off","snis":[],"probe_url":"https://cp.cloudflare.com/","concurrency":3}"#;
    let decoded: Phase2Config = serde_json::from_str(legacy).unwrap();
    assert!(decoded.probe_urls.is_empty());
    assert_eq!(
        decoded.probe_url, "https://cp.cloudflare.com/",
        "an explicit probe_url survives decoding"
    );
    let bare = r#"{"configs":["vless://uuid@example.com:443"],"fragment":"off","snis":[],"concurrency":3}"#;
    let decoded: Phase2Config = serde_json::from_str(bare).unwrap();
    assert_eq!(decoded.probe_url, DEFAULT_PROBE_URL);
}

#[test]
fn phase2_verdict_config_index_defaults_to_none() {
    let legacy = r#"{"passed":true,"fragment":"light","sni":"","latency_ms":42}"#;
    let v: Phase2Verdict = serde_json::from_str(legacy).unwrap();
    assert_eq!(
        v.config_index, None,
        "omitted field must deserialize as None"
    );
    let json = serde_json::to_string(&Phase2Verdict {
        passed: true,
        fragment: FragmentPreset::Light,
        sni: "a.me".to_owned(),
        latency_ms: Some(7),
        error: None,
        config_index: Some(2),
        verifier: Some(Verifier::Inline),
        speed_test_mbps: None,
    })
    .unwrap();
    assert!(json.contains("\"config_index\":2"), "{json}");
}

#[test]
fn phase2_verdict_speed_defaults_to_none_and_round_trips() {
    let legacy = r#"{"passed":true,"fragment":"light","sni":"","latency_ms":42}"#;
    let v: Phase2Verdict = serde_json::from_str(legacy).unwrap();
    assert_eq!(v.speed_test_mbps, None);
    let measured = Phase2Verdict {
        passed: true,
        fragment: FragmentPreset::Light,
        sni: "a.me".to_owned(),
        latency_ms: Some(7),
        error: None,
        config_index: Some(0),
        verifier: None,
        speed_test_mbps: Some(12.5),
    };
    let json = serde_json::to_string(&measured).unwrap();
    assert!(json.contains("\"speed_test_mbps\":12.5"), "{json}");
    let back: Phase2Verdict = serde_json::from_str(&json).unwrap();
    assert_eq!(measured, back);
}

#[test]
fn speed_test_fields_validate_and_round_trip() {
    let mut c = valid_config();
    assert!(!c.speed_test);
    assert_eq!(c.min_speed_mbps, None);
    c.speed_test = true;
    assert_eq!(
        c.validate(),
        Err(ConfigError::SpeedTestNeedsConfigs),
        "the speed test samples through phase-2 tunnels, so configs are mandatory"
    );
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        ..Default::default()
    });
    assert_eq!(c.validate(), Ok(()));
    c.min_speed_mbps = Some(0.0);
    assert_eq!(c.validate(), Err(ConfigError::InvalidMinSpeed));
    c.min_speed_mbps = Some(f32::NAN);
    assert_eq!(c.validate(), Err(ConfigError::InvalidMinSpeed));
    c.min_speed_mbps = Some(-1.0);
    assert_eq!(c.validate(), Err(ConfigError::InvalidMinSpeed));
    c.min_speed_mbps = Some(3.5);
    assert_eq!(c.validate(), Ok(()));
    let json = serde_json::to_string(&c).unwrap();
    let back: ScanConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn speed_test_fields_default_when_absent() {
    let legacy = r#"{"mode":"Cdn","target":{"Count":350},"ports":[443],"stop":{"found":20,"cap":null},"exclude":[],"custom_cidrs":[],"concurrency":64,"timeout_ms":3000}"#;
    let c: ScanConfig = serde_json::from_str(legacy).unwrap();
    assert!(!c.speed_test, "the speed test is strictly opt-in");
    assert_eq!(c.min_speed_mbps, None);
}

#[test]
fn min_speed_requires_speed_test() {
    let mut c = valid_config();
    c.min_speed_mbps = Some(5.0);
    assert_eq!(c.validate(), Err(ConfigError::MinSpeedNeedsSpeedTest));
    c.speed_test = true;
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        ..Default::default()
    });
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_speed_test_in_warp_mode() {
    let mut c = valid_config();
    c.mode = Mode::Warp;
    c.ports = vec![Port::new(2408)];
    c.warp = Some(WarpConfig::default());
    c.speed_test = true;
    assert_eq!(c.validate(), Err(ConfigError::SpeedTestWrongMode));
}

#[test]
fn custom_fragment_requires_values() {
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        fragment: FragmentPreset::Custom,
        ..Default::default()
    });
    assert_eq!(c.validate(), Err(ConfigError::MissingCustomFragment));
}

#[test]
fn rejects_out_of_range_concurrency_and_timeout() {
    let mut c = valid_config();
    c.concurrency = 0;
    assert_eq!(c.validate(), Err(ConfigError::InvalidConcurrency(0)));
    let mut c = valid_config();
    c.concurrency = 1001;
    assert_eq!(c.validate(), Err(ConfigError::InvalidConcurrency(1001)));
    let mut c = valid_config();
    c.timeout_ms = 50;
    assert_eq!(c.validate(), Err(ConfigError::InvalidTimeout(50)));
}

#[test]
fn rejects_bad_warp_endpoints() {
    let w = WarpConfig {
        custom_endpoints: vec!["1.2.3.4:0".to_owned()],
        ..Default::default()
    };
    assert_eq!(
        w.validate(),
        Err(ConfigError::InvalidEndpoint(
            "1.2.3.4:0".to_owned(),
            "port is 0".to_owned()
        ))
    );
    let w = WarpConfig {
        custom_endpoints: vec!["::1".to_owned()],
        ..Default::default()
    };
    assert!(w.validate().is_err());
    let w = WarpConfig {
        custom_endpoints: vec!["1.2.3.4:2408".to_owned(), "5.6.7.8".to_owned()],
        ..Default::default()
    };
    assert_eq!(w.validate(), Ok(()));
}

#[test]
fn rejects_bad_probes_per_endpoint() {
    let w = WarpConfig {
        probes_per_endpoint: 0,
        ..Default::default()
    };
    assert_eq!(w.validate(), Err(ConfigError::InvalidProbes(0)));
    let w = WarpConfig {
        probes_per_endpoint: 11,
        ..Default::default()
    };
    assert_eq!(w.validate(), Err(ConfigError::InvalidProbes(11)));
}

#[test]
fn verify_without_wgconf_is_rejected() {
    let w = WarpConfig {
        verify_with_wgconf: true,
        ..Default::default()
    };
    assert_eq!(w.validate(), Err(ConfigError::VerifyNeedsWgconf));
    let w = WarpConfig {
        verify_with_wgconf: true,
        wgconf: Some("anything".to_owned()),
        ..Default::default()
    };
    assert_eq!(w.validate(), Ok(()));
}

#[test]
fn serde_round_trip_scan_config() {
    let c = valid_config();
    let json = serde_json::to_string(&c).unwrap();
    let back: ScanConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn serde_round_trip_scan_event() {
    for event in [
        ScanEvent::Progress(ScanProgress {
            scanned: 1,
            found: 2,
            total: None,
        }),
        ScanEvent::Result(Box::new(Verdict {
            ip: "1.2.3.4".parse().unwrap(),
            port: 443,
            latency_ms: Some(42),
            country: Some("IR".to_owned()),
            colo: None,
            phase2: None,
            sent: 1,
            received: 1,
            loss_pct: Some(0),
            fail_reason: None,
        })),
        ScanEvent::Finished(ScanSummary {
            scanned: 10,
            found: 2,
            duration_ms: 5,
            cancelled: false,
        }),
    ] {
        let json = serde_json::to_string(&event).unwrap();
        let back: ScanEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back, "round-trip failed for {json}");
    }
}

#[test]
fn verdict_new_fields_default_when_absent() {
    let legacy = r#"{"ip":"1.2.3.4","port":443,"latency_ms":42}"#;
    let v: Verdict = serde_json::from_str(legacy).unwrap();
    assert_eq!(v.sent, 0);
    assert_eq!(v.received, 0);
    assert_eq!(v.loss_pct, None);
    assert_eq!(
        v.fail_reason, None,
        "omitted fields must deserialize as defaults"
    );
}

#[test]
fn loss_threshold_and_idle_hold_validate_and_round_trip() {
    let mut c = valid_config();
    assert_eq!(c.loss_threshold, None);
    assert_eq!(c.idle_hold_ms, 0);
    c.loss_threshold = Some(101);
    assert_eq!(c.validate(), Err(ConfigError::InvalidLossThreshold(101)));
    c.loss_threshold = Some(100);
    assert_eq!(c.validate(), Ok(()));
    c.idle_hold_ms = MAX_IDLE_HOLD_MS + 1;
    assert_eq!(
        c.validate(),
        Err(ConfigError::InvalidIdleHold(MAX_IDLE_HOLD_MS + 1))
    );
    c.idle_hold_ms = 5_000;
    assert_eq!(c.validate(), Ok(()));
    let json = serde_json::to_string(&c).unwrap();
    let back: ScanConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, back);
}

#[test]
fn event_tags_are_snake_case() {
    let json = serde_json::to_string(&ScanEvent::Finished(ScanSummary {
        scanned: 0,
        found: 0,
        duration_ms: 0,
        cancelled: false,
    }))
    .unwrap();
    assert!(json.contains("\"type\":\"finished\""), "{json}");
}

#[test]
fn summary_cancelled_defaults_to_false() {
    let json = r#"{"scanned":1,"found":0,"duration_ms":10}"#;
    let s: ScanSummary = serde_json::from_str(json).unwrap();
    assert!(!s.cancelled, "omitted field must deserialize as false");
    let event_json = r#"{"type":"finished","scanned":1,"found":0,"duration_ms":10}"#;
    let event: ScanEvent = serde_json::from_str(event_json).unwrap();
    assert!(matches!(event, ScanEvent::Finished(s) if !s.cancelled));
}

#[test]
fn summary_cancelled_round_trips() {
    let s = ScanSummary {
        scanned: 7,
        found: 3,
        duration_ms: 42,
        cancelled: true,
    };
    let json = serde_json::to_string(&s).unwrap();
    assert!(json.contains("\"cancelled\":true"), "{json}");
    assert_eq!(serde_json::from_str::<ScanSummary>(&json).unwrap(), s);
}

#[test]
fn ports_are_deduped_for_the_cap() {
    let mut c = valid_config();
    c.ports = (0..100).map(|_| Port::new(443)).collect();
    assert_eq!(c.validate(), Ok(()));
    let mut c = valid_config();
    c.ports = vec![
        Port::new(443),
        Port::new(8443),
        Port::new(443),
        Port::new(2408),
        Port::new(443),
    ];
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_too_many_unique_ports() {
    let mut c = valid_config();
    c.ports = (1..=65).map(Port::new).collect();
    assert_eq!(c.validate(), Err(ConfigError::TooManyPorts(65)));
    let mut c = valid_config();
    c.ports = (1..=MAX_PORTS as u16).map(Port::new).collect();
    assert_eq!(c.validate(), Ok(()), "64 unique ports must be accepted");
}

#[test]
fn rejects_too_many_exclude_and_custom_cidrs() {
    let mut c = valid_config();
    c.exclude = (0..=MAX_CIDRS).map(|i| format!("203.0.{i}.0/24")).collect();
    assert_eq!(
        c.validate(),
        Err(ConfigError::TooManyExcludes(MAX_CIDRS + 1))
    );
    let mut c = valid_config();
    c.custom_cidrs = (0..=MAX_CIDRS).map(|i| format!("203.0.{i}.0/24")).collect();
    assert_eq!(c.validate(), Err(ConfigError::TooManyCidrs(MAX_CIDRS + 1)));
    let mut c = valid_config();
    c.custom_cidrs = (0..MAX_CIDRS).map(|i| format!("203.0.{i}.0/24")).collect();
    assert_eq!(c.validate(), Ok(()), "64 CIDRs must be accepted");
}

#[test]
fn rejects_too_many_phase2_configs_and_snis() {
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: (0..=MAX_PHASE2_ENTRIES)
            .map(|i| format!("vless://uuid@example.com:{i}"))
            .collect(),
        ..Default::default()
    });
    assert_eq!(
        c.validate(),
        Err(ConfigError::TooManyConfigs(MAX_PHASE2_ENTRIES + 1))
    );
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        snis: (0..=MAX_PHASE2_ENTRIES)
            .map(|i| format!("sni{i}.example.com"))
            .collect(),
        ..Default::default()
    });
    assert_eq!(
        c.validate(),
        Err(ConfigError::TooManySnis(MAX_PHASE2_ENTRIES + 1))
    );
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: (0..MAX_PHASE2_ENTRIES)
            .map(|i| format!("vless://uuid@example.com:{i}"))
            .collect(),
        snis: (0..MAX_PHASE2_ENTRIES)
            .map(|i| format!("sni{i}.example.com"))
            .collect(),
        ..Default::default()
    });
    assert_eq!(c.validate(), Ok(()), "8 configs + 8 snis must be accepted");
}

#[test]
fn rejects_malformed_custom_fragment_values() {
    for (field, bad) in [
        ("packets", "nope"),
        ("packets", ""),
        ("packets", "1-2-3"),
        ("packets", "-5"),
        ("packets", "5-"),
        ("length", "abc"),
        ("length", "100,200"),
        ("length", "1 0"),
        ("length", ""),
        ("interval", "10.5"),
        ("interval", "10-20-30"),
    ] {
        let f = CustomFragment {
            packets: "tlshello".to_owned(),
            length: "100-200".to_owned(),
            interval: "10-20".to_owned(),
        };
        let f = match field {
            "packets" => CustomFragment {
                packets: bad.to_owned(),
                ..f
            },
            "length" => CustomFragment {
                length: bad.to_owned(),
                ..f
            },
            _ => CustomFragment {
                interval: bad.to_owned(),
                ..f
            },
        };
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            fragment: FragmentPreset::Custom,
            custom_fragment: Some(f),
            ..Default::default()
        });
        assert!(
            matches!(c.validate(), Err(ConfigError::InvalidFragment(f, _)) if f == field),
            "expected {bad:?} in {field} to be rejected"
        );
    }
}

#[test]
fn accepts_valid_custom_fragment_values() {
    for (packets, length, interval) in [
        ("tlshello", "100", "10"),
        ("tlshello", "100-200", "10-20"),
        ("1-3", "100-200", "10-20"),
        ("2", "50", "5-50"),
    ] {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            fragment: FragmentPreset::Custom,
            custom_fragment: Some(CustomFragment {
                packets: packets.to_owned(),
                length: length.to_owned(),
                interval: interval.to_owned(),
            }),
            ..Default::default()
        });
        assert_eq!(c.validate(), Ok(()), "{packets}/{length}/{interval}");
    }
}

#[test]
fn rejects_out_of_bounds_custom_fragment_ranges() {
    for (field, bad) in [
        ("length", "0"),
        ("length", "0-100"),
        ("length", "100-0"),
        ("length", "65536"),
        ("length", "1-70000"),
        ("length", "200-100"),
        ("interval", "0-10"),
        ("interval", "1-60001"),
        ("interval", "50000-100"),
    ] {
        let mut c = valid_config();
        c.phase2 = Some(Phase2Config {
            configs: vec!["vless://uuid@example.com:443".to_owned()],
            fragment: FragmentPreset::Custom,
            custom_fragment: Some(CustomFragment {
                packets: "tlshello".to_owned(),
                length: "100-200".to_owned(),
                interval: "10-20".to_owned(),
            }),
            ..Default::default()
        });
        let cf = c.phase2.as_mut().unwrap().custom_fragment.as_mut().unwrap();
        match field {
            "length" => cf.length = bad.to_owned(),
            "interval" => cf.interval = bad.to_owned(),
            _ => unreachable!(),
        }
        assert!(
            matches!(c.validate(), Err(ConfigError::InvalidFragmentRange(f, _)) if f == field),
            "expected {bad:?} in {field} to be rejected"
        );
    }
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        fragment: FragmentPreset::Custom,
        custom_fragment: Some(CustomFragment {
            packets: "tlshello".to_owned(),
            length: "1-65535".to_owned(),
            interval: "1-60000".to_owned(),
        }),
        ..Default::default()
    });
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_stop_values_above_the_frontend_cap() {
    let mut c = valid_config();
    c.stop.found = MAX_STOP_VALUE + 1;
    assert_eq!(
        c.validate(),
        Err(ConfigError::InvalidFoundUpper(MAX_STOP_VALUE + 1))
    );
    let mut c = valid_config();
    c.stop = StopCondition {
        found: 1,
        cap: Some(0),
    };
    assert_eq!(c.validate(), Err(ConfigError::InvalidCap(0)));
    let mut c = valid_config();
    c.stop = StopCondition {
        found: 1,
        cap: Some(MAX_STOP_VALUE + 1),
    };
    assert_eq!(
        c.validate(),
        Err(ConfigError::InvalidCap(MAX_STOP_VALUE + 1))
    );
    let mut c = valid_config();
    c.stop = StopCondition {
        found: MAX_STOP_VALUE,
        cap: Some(MAX_STOP_VALUE),
    };
    assert_eq!(c.validate(), Ok(()));
}

fn phase2_with_snis(snis: Vec<String>) -> ScanConfig {
    let mut c = valid_config();
    c.phase2 = Some(Phase2Config {
        configs: vec!["vless://uuid@example.com:443".to_owned()],
        snis,
        ..Default::default()
    });
    c
}

#[test]
fn accepts_valid_snis() {
    let max_label = "x".repeat(MAX_SNI_LABEL_CHARS);
    for good in [
        "www.cloudflare.com",
        "a",
        "a-b.c-d.e",
        "1.2.3.4",
        "2606:4700::1111",
        max_label.as_str(),
    ] {
        assert_eq!(validate_sni(good), Ok(()), "expected {good:?} to pass");
    }
    let max_host = format!(
        "{}.{}.{}.{}",
        "a".repeat(MAX_SNI_LABEL_CHARS),
        "a".repeat(MAX_SNI_LABEL_CHARS),
        "a".repeat(MAX_SNI_LABEL_CHARS),
        "a".repeat(MAX_SNI_HOSTNAME_CHARS - 3 * MAX_SNI_LABEL_CHARS - 3)
    );
    assert_eq!(max_host.len(), MAX_SNI_HOSTNAME_CHARS);
    assert_eq!(validate_sni(&max_host), Ok(()));
    let c = phase2_with_snis(vec!["www.cloudflare.com".to_owned(), "1.2.3.4".to_owned()]);
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_invalid_snis() {
    let too_long = "a".repeat(MAX_SNI_HOSTNAME_CHARS + 1);
    let long_label = format!("{}.a", "a".repeat(MAX_SNI_LABEL_CHARS + 1));
    for bad in [
        "",
        "bad_sni",
        "sni with space",
        "-leading",
        "trailing-",
        "a.-b",
        "a.b-",
        "a..b",
        ".a",
        "a.",
        "ünïcode.example",
        too_long.as_str(),
        long_label.as_str(),
        "a,b",
    ] {
        assert!(
            matches!(validate_sni(bad), Err(ConfigError::InvalidSni(_, _))),
            "expected {bad:?} to be rejected"
        );
    }
    let c = phase2_with_snis(vec!["".to_owned()]);
    assert!(matches!(c.validate(), Err(ConfigError::InvalidSni(_, _))));
    let c = phase2_with_snis(vec!["ok.example".to_owned(), "nope_sni".to_owned()]);
    assert!(matches!(c.validate(), Err(ConfigError::InvalidSni(_, _))));
    let c = phase2_with_snis(vec![]);
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn parse_endpoint_accepts_ip_with_and_without_port() {
    assert_eq!(
        parse_endpoint("1.2.3.4").unwrap(),
        ("1.2.3.4".parse::<IpAddr>().unwrap(), None)
    );
    assert_eq!(
        parse_endpoint("1.2.3.4:2408").unwrap(),
        ("1.2.3.4".parse::<IpAddr>().unwrap(), Some(2408))
    );
    assert_eq!(
        parse_endpoint(" 1.2.3.4 : 443 ").unwrap(),
        ("1.2.3.4".parse::<IpAddr>().unwrap(), Some(443))
    );
}

#[test]
fn parse_endpoint_rejects_invalid_input() {
    for bad in [
        "garbage",
        "1.2.3.4:abc",
        "1.2.3.4:0",
        "1.2.3.4:99999",
        "::1",
        "::1:443",
        "1.2.3.4:443:443",
    ] {
        assert!(
            parse_endpoint(bad).is_err(),
            "expected {bad} to be rejected"
        );
    }
}

#[test]
fn validate_endpoint_and_parse_endpoint_agree() {
    for good in ["1.2.3.4", "1.2.3.4:2408", "1.2.3.4:443"] {
        let w = WarpConfig {
            custom_endpoints: vec![good.to_owned()],
            ..Default::default()
        };
        assert_eq!(w.validate(), Ok(()), "{good}");
    }
    for bad in ["::1", "1.2.3.4:0", "1.2.3.4:abc"] {
        let w = WarpConfig {
            custom_endpoints: vec![bad.to_owned()],
            ..Default::default()
        };
        assert!(w.validate().is_err(), "{bad}");
    }
}

#[test]
fn cidr_validation_delegates_to_ranges_parser() {
    for good in ["1.2.3.99/24", "203.0.113.0/24", "2001:db8::1/64"] {
        let mut c = valid_config();
        c.custom_cidrs = vec![good.to_owned()];
        assert_eq!(c.validate(), Ok(()), "{good}");
    }
    for bad in [
        "garbage",
        "1.2.3.4/33",
        "2606:4700::/129",
        "::/0",
        "1.2.3.4/abc",
    ] {
        let mut c = valid_config();
        c.custom_cidrs = vec![bad.to_owned()];
        assert!(c.validate().is_err(), "{bad}");
    }
}

#[test]
fn rejects_non_routable_custom_cidrs() {
    for cidr in [
        "127.0.0.1/32",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.1.0/24",
        "100.64.0.0/10",
        "100.127.255.255/32",
        "::1/128",
        "::/128",
        "fc00::/7",
        "fe80::/10",
        "::ffff:127.0.0.1/128",
        "::ffff:169.254.0.1/128",
        "::ffff:10.0.0.0/104",
        "::ffff:192.168.1.0/120",
        "::ffff:100.64.0.1/128",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "255.255.255.255/32",
        "::ffff:224.0.0.1/128",
    ] {
        let mut c = valid_config();
        c.custom_cidrs = vec![cidr.to_owned()];
        assert!(
            matches!(c.validate(), Err(ConfigError::NonRoutableCidr(_))),
            "custom_cidrs {cidr} must be rejected"
        );
    }
    assert_eq!(valid_config().validate(), Ok(()));
}

#[test]
fn rejects_non_routable_warp_endpoints() {
    let mut c = valid_config();
    c.mode = Mode::Warp;
    c.custom_cidrs = vec![];
    c.ports = vec![Port::new(2408)];
    c.warp = Some(WarpConfig {
        custom_endpoints: vec!["127.0.0.1".to_owned()],
        ..WarpConfig::default()
    });
    assert!(matches!(
        c.validate(),
        Err(ConfigError::NonRoutableEndpoint(_))
    ));
    c.warp.as_mut().unwrap().custom_endpoints = vec!["224.0.0.1".to_owned()];
    assert!(matches!(
        c.validate(),
        Err(ConfigError::NonRoutableEndpoint(_))
    ));
    c.warp.as_mut().unwrap().custom_endpoints = vec!["203.0.113.1".to_owned()];
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn rejects_default_warp_port_in_warp_mode() {
    let mut c = valid_config();
    c.mode = Mode::Warp;
    c.custom_cidrs = vec![];
    c.ports = vec![Port::new(DEFAULT_PORT)];
    c.warp = Some(WarpConfig {
        custom_endpoints: vec!["203.0.113.1".to_owned()],
        ..WarpConfig::default()
    });
    assert_eq!(c.validate(), Err(ConfigError::DefaultWarpPort));
    c.ports = vec![Port::new(2408), Port::new(500)];
    assert_eq!(c.validate(), Ok(()));
}

#[test]
fn default_warp_port_not_rejected_in_cdn_mode() {
    let c = valid_config();
    assert_eq!(c.validate(), Ok(()));
}
