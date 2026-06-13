use agentmesh::prompt_injection::{DetectionOptions, PromptInjectionDetector};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

#[derive(Default, Clone, Debug)]
struct Tally {
    attacks: u64,
    attacks_caught: u64,
    benign: u64,
    benign_flagged: u64,
}

impl Tally {
    fn observe(&mut self, is_attack: bool, pred_attack: bool) {
        if is_attack {
            self.attacks += 1;
            if pred_attack {
                self.attacks_caught += 1;
            }
        } else {
            self.benign += 1;
            if pred_attack {
                self.benign_flagged += 1;
            }
        }
    }

    fn as_json(&self) -> Value {
        json!({
            "attacks": self.attacks,
            "attacks_caught": self.attacks_caught,
            "attack_recall": ratio(self.attacks_caught, self.attacks),
            "benign": self.benign,
            "benign_flagged": self.benign_flagged,
            "benign_fp_rate": ratio(self.benign_flagged, self.benign),
        })
    }
}

fn ratio(n: u64, d: u64) -> Option<f64> {
    if d == 0 {
        None
    } else {
        Some((n as f64) / (d as f64))
    }
}

#[derive(Debug)]
struct Args {
    corpus: PathBuf,
    split: Option<String>,
    per_row: Option<PathBuf>,
    summary: Option<PathBuf>,
}

fn parse_args() -> Args {
    let mut raw = std::env::args().skip(1);
    let corpus = raw
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| usage_and_exit());
    let mut split = None;
    let mut per_row = None;
    let mut summary = None;

    while let Some(arg) = raw.next() {
        match arg.as_str() {
            "--split" => {
                split = Some(raw.next().unwrap_or_else(|| usage_and_exit()));
            }
            "--per-row" => {
                per_row = Some(PathBuf::from(raw.next().unwrap_or_else(|| usage_and_exit())));
            }
            "--summary" => {
                summary = Some(PathBuf::from(raw.next().unwrap_or_else(|| usage_and_exit())));
            }
            _ => usage_and_exit(),
        }
    }

    Args {
        corpus,
        split,
        per_row,
        summary,
    }
}

fn usage_and_exit() -> ! {
    eprintln!(
        "usage: agt-prompt-injection-baseline <corpus.jsonl> [--split SPLIT] [--per-row out.jsonl] [--summary summary.json]"
    );
    std::process::exit(2);
}

fn val_str<'a>(row: &'a Value, key: &str) -> &'a str {
    row.get(key).and_then(Value::as_str).unwrap_or("")
}

fn val_bool(row: &Value, key: &str) -> bool {
    row.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = parse_args();
    let file = File::open(&args.corpus)?;
    let reader = BufReader::new(file);
    let mut detector = PromptInjectionDetector::new()?;
    let mut per_row_records = Vec::new();

    let mut overall = Tally::default();
    let mut by_attack_class: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_benign_subclass: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_bypass_class: BTreeMap<String, Tally> = BTreeMap::new();
    let mut by_split: BTreeMap<String, Tally> = BTreeMap::new();
    let mut processed = 0_u64;

    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let row: Value = serde_json::from_str(&line)
            .map_err(|err| format!("{}:{} invalid JSON: {err}", args.corpus.display(), lineno + 1))?;
        let split = val_str(&row, "split");
        if let Some(want) = &args.split {
            if split != want {
                continue;
            }
        }

        let id = val_str(&row, "id");
        let text = val_str(&row, "text");
        let attack_class = val_str(&row, "attack_class");
        let benign_subclass = val_str(&row, "benign_subclass");
        let bypass_class = val_str(&row, "bypass_class");
        let source_type = val_str(&row, "source_type");
        let trust_level = val_str(&row, "trust_level");
        let is_attack = attack_class != "benign";

        let result = detector.detect_with_options(
            text,
            DetectionOptions {
                source: format!("prompt-injection-fixture:{source_type}:{trust_level}:{split}"),
                canary_tokens: Vec::new(),
            },
        );
        let pred_attack = result.is_injection;

        overall.observe(is_attack, pred_attack);
        by_attack_class
            .entry(attack_class.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        by_benign_subclass
            .entry(benign_subclass.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        by_bypass_class
            .entry(bypass_class.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        by_split
            .entry(split.to_string())
            .or_default()
            .observe(is_attack, pred_attack);
        processed += 1;

        if args.per_row.is_some() {
            per_row_records.push(json!({
                "id": id,
                "split": split,
                "family_id": val_str(&row, "family_id"),
                "group_id": val_str(&row, "group_id"),
                "attack_class": attack_class,
                "benign_subclass": benign_subclass,
                "bypass_class": bypass_class,
                "source_type": source_type,
                "trust_level": trust_level,
                "expected_action": val_str(&row, "expected_action"),
                "requires_tool_call": val_bool(&row, "requires_tool_call"),
                "contains_sensitive_sink": val_bool(&row, "contains_sensitive_sink"),
                "label_positive": is_attack,
                "rules_pred_attack": pred_attack,
                "threat_level": format!("{:?}", result.threat_level),
                "injection_type": result.injection_type.map(|t| format!("{:?}", t)),
                "confidence": result.confidence,
                "matched_patterns": result.matched_patterns,
            }));
        }
    }

    if let Some(path) = args.per_row {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut out = File::create(&path)?;
        for record in &per_row_records {
            writeln!(out, "{}", serde_json::to_string(record)?)?;
        }
    }

    let summary = json!({
        "corpus": args.corpus,
        "split_filter": args.split,
        "detector": "AGT Rust PromptInjectionDetector::new / Sensitivity::Balanced / default config",
        "raw_text_in_output": false,
        "processed": processed,
        "overall": overall.as_json(),
        "by_attack_class": map_json(&by_attack_class),
        "by_benign_subclass": map_json(&by_benign_subclass),
        "by_bypass_class": map_json(&by_bypass_class),
        "by_split": map_json(&by_split),
    });
    let rendered = serde_json::to_string_pretty(&summary)?;
    if let Some(path) = args.summary {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, format!("{rendered}\n"))?;
    }
    println!("{rendered}");
    Ok(())
}

fn map_json(map: &BTreeMap<String, Tally>) -> BTreeMap<String, Value> {
    map.iter()
        .map(|(key, tally)| (key.clone(), tally.as_json()))
        .collect()
}
