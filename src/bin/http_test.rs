//! Quick HTTP detection test

use crmonban::http_detect::DetectionEngine;

fn main() {
    let engine = DetectionEngine::from_file("data/http_detect/attack_patterns.json")
        .expect("Failed to load patterns");

    let test_urls = vec![
        ("/index.html", false),
        ("/../../../../etc/passwd", true),
        ("/user.php?id=1' OR '1'='1", true),
        ("/search?q=<script>alert(1)</script>", true),
        ("/wp-admin", true),
    ];

    println!("Testing HTTP detection:\n");
    let mut passed = 0;
    let mut failed = 0;

    for (url, should_detect) in test_urls {
        let results = engine.scan_url(url);
        let detected = !results.is_empty();
        let status = if detected == should_detect {
            passed += 1;
            "PASS"
        } else {
            failed += 1;
            "FAIL"
        };
        println!("[{}] {}", status, url);
        if !results.is_empty() {
            for r in &results {
                println!("      -> {} ({:?})", r.category, r.action);
            }
        }
        println!();
    }

    println!("Results: {} passed, {} failed", passed, failed);
}
