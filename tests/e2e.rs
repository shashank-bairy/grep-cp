//! End-to-end: rmcp client ↔ `grepcp serve --stdio` (child process) against a generated fixture.

#[path = "fixtures/gen.rs"]
mod fixtures;

use rmcp::model::{CallToolRequestParams, CallToolResult};
use rmcp::service::RunningService;
use rmcp::transport::{ConfigureCommandExt, TokioChildProcess};
use rmcp::{RoleClient, ServiceExt};
use serde_json::{Value, json};

struct Client {
    svc: RunningService<RoleClient, ()>,
    _fx: fixtures::Fixture,
}

async fn start(fx: fixtures::Fixture) -> Client {
    let cfg = fx.config.clone();
    let transport = TokioChildProcess::new(
        tokio::process::Command::new(env!("CARGO_BIN_EXE_grepcp")).configure(|c| {
            c.arg("serve")
                .arg("--stdio")
                .arg("--config")
                .arg(&cfg)
                .env("GREPCP_LOG", "warn");
        }),
    )
    .unwrap();
    let svc = ().serve(transport).await.unwrap();
    Client { svc, _fx: fx }
}

impl Client {
    async fn call(&self, tool: &str, args: Value) -> CallToolResult {
        let Value::Object(m) = args else {
            panic!("args must be an object")
        };
        self.svc
            .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(m))
            .await
            .unwrap()
    }

    async fn ok(&self, tool: &str, args: Value) -> Value {
        let r = self.call(tool, args.clone()).await;
        assert_ne!(r.is_error, Some(true), "{tool} {args} failed: {}", text(&r));
        r.structured_content.clone().expect("structured content")
    }

    async fn err(&self, tool: &str, args: Value) -> String {
        let r = self.call(tool, args.clone()).await;
        assert_eq!(
            r.is_error,
            Some(true),
            "{tool} {args} unexpectedly succeeded: {}",
            text(&r)
        );
        text(&r)
    }
}

fn text(r: &CallToolResult) -> String {
    r.content
        .iter()
        .filter_map(|c| c.as_text().map(|t| t.text.clone()))
        .collect::<Vec<_>>()
        .join("\n")
}

#[tokio::test]
async fn end_to_end() {
    let fx = fixtures::build();
    let id = fx.id.clone();
    let billing_unreadable = fx.billing_unreadable;
    let c = start(fx).await;

    // Tool list.
    let tools = c.svc.list_all_tools().await.unwrap();
    let mut names: Vec<_> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(
        names,
        [
            "count_matches",
            "grep_by_id",
            "grep_logs",
            "list_files",
            "list_services",
            "locate",
            "read_context",
            "server_info",
            "tail_live"
        ]
    );
    assert!(
        tools
            .iter()
            .all(|t| t.annotations.as_ref().and_then(|a| a.read_only_hint) == Some(true))
    );

    // server_info
    let v = c.ok("server_info", json!({})).await;
    assert_eq!(v["box"], "test1");
    assert_eq!(v["line_parsing"], true);

    // list_services
    let v = c.ok("list_services", json!({})).await;
    let svcs = v["services"].as_array().unwrap();
    let names: Vec<_> = svcs.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert_eq!(names, ["billing", "orders", "payments"]);
    if billing_unreadable {
        assert_eq!(svcs[0]["readable"], false);
    }
    assert_eq!(
        svcs[1]["description"],
        "Order API: create / update / cancel / status"
    );

    // list_files: parsed names only, no symlink escaping the root, no junk.
    let v = c.ok("list_files", json!({"service": "orders"})).await;
    let files: Vec<_> = v["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| f["file"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(files.len(), 2 * (fixtures::HOURS as usize + 1));
    assert!(!files.iter().any(|f| f == "evil.log" || f == "junk.txt"));
    let v = c
        .ok(
            "list_files",
            json!({"service": "orders", "host": "web-1", "last": "30m"}),
        )
        .await;
    assert!(
        v["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["host"] == "web-1")
    );

    // grep_logs: ERROR lines over 3h, chronological, redacted, with offsets.
    let v = c
        .ok(
            "grep_logs",
            json!({"service": "orders", "pattern": "ERROR", "last": "3h"}),
        )
        .await;
    let lines = v["lines"].as_array().unwrap();
    assert!(lines.len() >= 30, "got {}", lines.len());
    let ts: Vec<_> = lines
        .iter()
        .map(|l| l["ts"].as_str().unwrap().to_string())
        .collect();
    let mut sorted = ts.clone();
    sorted.sort();
    assert_eq!(ts, sorted, "results must be chronological");
    for l in lines {
        let t = l["text"].as_str().unwrap();
        assert!(t.contains("bearer <redacted>"), "{t}");
        assert!(!t.contains("tok"), "{t}");
        assert!(l["byte_offset"].is_u64());
        assert_eq!(l["fields"]["level"], "ERROR");
        // Fields are derived from the redacted text, never the raw line.
        let msg = l["fields"]["msg"].as_str().unwrap();
        assert!(
            msg.contains("bearer <redacted>") && !msg.contains("tok"),
            "{msg}"
        );
    }
    assert!(v["files_scanned"].as_u64().unwrap() >= 6);
    assert!(v["files_skipped_by_time"].as_u64().unwrap() > 0);

    // Context lines: the stack trace follows each ERROR line.
    let v = c
        .ok("grep_logs", json!({"service": "orders", "pattern": "ERROR", "last": "2h", "after": 2, "max_lines": 2}))
        .await;
    let l0 = &v["lines"][0];
    assert_eq!(
        l0["context_after"][1],
        "\tat com.example.Pay.charge(Pay.java:42)"
    );
    assert_eq!(v["truncated"], true);

    // order=last returns the most recent lines.
    let first = c
        .ok(
            "grep_logs",
            json!({"service": "orders", "pattern": "status=200", "last": "3h", "max_lines": 5}),
        )
        .await;
    let last = c
        .ok("grep_logs", json!({"service": "orders", "pattern": "status=200", "last": "3h", "max_lines": 5, "order": "last"}))
        .await;
    let f_ts = first["lines"][0]["ts"].as_str().unwrap();
    let l_ts = last["lines"][4]["ts"].as_str().unwrap();
    assert!(l_ts > f_ts);
    assert_eq!(last["lines"].as_array().unwrap().len(), 5);

    // Regex mode + host filter.
    let v = c
        .ok("grep_logs", json!({"service": "orders", "pattern": "latency_ms=49[0-9]\\b", "fixed_string": false, "last": "3h", "hosts": ["web-2"]}))
        .await;
    let lines = v["lines"].as_array().unwrap();
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|l| l["host"] == "web-2"));

    // date + hours window.
    let h = (chrono::Utc::now() - chrono::Duration::hours(2))
        .format("%Y-%m-%d %H")
        .to_string();
    let (date, hour) = h.split_once(' ').unwrap();
    let v = c
        .ok("count_matches", json!({"service": "orders", "pattern": "ERROR", "date": date, "hours": [hour.parse::<u32>().unwrap()]}))
        .await;
    // 6 errors per hour per host.
    assert_eq!(v["total"], 12, "{v}");

    // count_matches by bucket and minute.
    let v = c
        .ok(
            "count_matches",
            json!({"service": "orders", "pattern": "ERROR", "last": "5h", "group_by": "bucket"}),
        )
        .await;
    assert!(v["groups"].as_array().unwrap().len() >= 5);
    let v = c
        .ok(
            "count_matches",
            json!({"service": "orders", "pattern": "ERROR", "last": "1h", "group_by": "minute"}),
        )
        .await;
    for g in v["groups"].as_array().unwrap() {
        assert_eq!(g["count"], 2, "{g}"); // one per host per error minute
    }

    // grep_by_id: decoded window, decoder's service.
    let v = c.ok("grep_by_id", json!({"id": id})).await;
    let lines = v["lines"].as_array().unwrap();
    assert_eq!(lines.len(), 1, "{v}");
    assert_eq!(lines[0]["host"], "web-1");
    assert!(
        v["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap().contains("derived from id"))
    );

    // locate: finds the id in orders/web-1 and payments/pay-1.
    let v = c.ok("locate", json!({"pattern": id})).await;
    let hits: Vec<_> = v["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            format!(
                "{}/{}",
                h["service"].as_str().unwrap(),
                h["host"].as_str().unwrap()
            )
        })
        .collect();
    assert_eq!(hits, ["orders/web-1", "payments/pay-1"]);

    // tail_live
    let v = c
        .ok("tail_live", json!({"service": "orders", "lines": 3}))
        .await;
    let files = v["files"].as_array().unwrap();
    assert_eq!(files.len(), 2);
    for f in files {
        assert!(!f["lines"].as_array().unwrap().is_empty());
    }

    // read_context on a hit inside a gzip file.
    let v = c
        .ok(
            "grep_logs",
            json!({"service": "orders", "pattern": "ERROR", "last": "4h", "max_lines": 1}),
        )
        .await;
    let hit = &v["lines"][0];
    assert!(hit["file"].as_str().unwrap().ends_with(".gz"));
    let ctx = c
        .ok(
            "read_context",
            json!({"service": "orders", "file": hit["file"], "byte_offset": hit["byte_offset"], "before": 1, "after": 2}),
        )
        .await;
    assert_eq!(ctx["line"]["text"], hit["text"]);
    assert_eq!(ctx["after"].as_array().unwrap().len(), 2);
    assert_eq!(ctx["before"].as_array().unwrap().len(), 1);

    // Multi-service search.
    let v = c
        .ok(
            "grep_logs",
            json!({"services": ["orders", "payments"], "pattern": id, "last": "4h"}),
        )
        .await;
    let svcs: std::collections::BTreeSet<_> = v["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l["service"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(svcs.into_iter().collect::<Vec<_>>(), ["orders", "payments"]);

    // Errors.
    let e = c
        .err("grep_logs", json!({"service": "ordrs", "pattern": "x"}))
        .await;
    assert!(e.contains("did you mean 'orders'"), "{e}");
    let e = c
        .err("grep_logs", json!({"service": "../etc", "pattern": "x"}))
        .await;
    assert!(e.contains("not valid"), "{e}");
    let e = c
        .err(
            "read_context",
            json!({"service": "orders", "file": "../../config.toml", "byte_offset": 0}),
        )
        .await;
    assert!(e.contains("unknown file"), "{e}");
    let e = c
        .err(
            "read_context",
            json!({"service": "orders", "file": "evil.log", "byte_offset": 0}),
        )
        .await;
    assert!(e.contains("unknown file"), "{e}");
    let e = c
        .err(
            "grep_logs",
            json!({"service": "orders", "pattern": "x", "last": "3d"}),
        )
        .await;
    assert!(e.contains("at most 24h"), "{e}");
    let e = c.err("grep_logs", json!({"service": "orders", "pattern": "x", "from": "2020-01-01 00:00", "to": "2020-01-01 01:00"})).await;
    assert!(e.contains("retention"), "{e}");
    let e = c
        .err(
            "grep_logs",
            json!({"service": "orders", "pattern": "(", "fixed_string": false}),
        )
        .await;
    assert!(e.contains("invalid pattern"), "{e}");
    let e = c
        .err(
            "grep_logs",
            json!({"service": "orders", "pattern": "x", "from": "01-06-2026 10:00"}),
        )
        .await;
    assert!(e.contains("YYYY-MM-DD"), "{e}");
    if billing_unreadable {
        let e = c.err("list_files", json!({"service": "billing"})).await;
        assert!(e.contains("not readable"), "{e}");
    }

    c.svc.cancel().await.unwrap();
}
