//! Packet recording and output
//!
//! Records sent packets to CSV/JSON for correlation with crmonban logs.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use chrono::Utc;
use serde::Serialize;

use crate::attacks::AttackType;
use crate::generator::PacketRecord;

/// Recording format
#[derive(Debug, Clone, Copy)]
pub enum RecordFormat {
    Csv,
    Json,
    JsonLines,
}

/// Packet recorder
pub struct Recorder {
    format: RecordFormat,
    writer: BufWriter<File>,
    records_written: u64,
}

impl Recorder {
    /// Create a new recorder
    pub fn new(path: &Path, format: RecordFormat) -> anyhow::Result<Self> {
        let file = File::create(path)?;
        let mut writer = BufWriter::new(file);

        // Write header for CSV
        if matches!(format, RecordFormat::Csv) {
            writeln!(writer, "id,timestamp,attack_type,src_ip,dst_ip,src_port,dst_port,protocol,tcp_flags,payload_size,payload_hash,seq,ack")?;
        }

        // Write opening bracket for JSON array
        if matches!(format, RecordFormat::Json) {
            writeln!(writer, "[")?;
        }

        Ok(Self {
            format,
            writer,
            records_written: 0,
        })
    }

    /// Write a single record
    pub fn write(&mut self, record: &PacketRecord) -> anyhow::Result<()> {
        match self.format {
            RecordFormat::Csv => {
                writeln!(
                    self.writer,
                    "{},{},{},{},{},{},{},{},{},{},{},{},{}",
                    record.id,
                    record.timestamp.format("%Y-%m-%dT%H:%M:%S%.6fZ"),
                    record.attack_type,
                    record.src_ip,
                    record.dst_ip,
                    record.src_port,
                    record.dst_port,
                    record.protocol,
                    record.tcp_flags.map(|f| f.to_string()).unwrap_or_default(),
                    record.payload_size,
                    record.payload_hash.as_deref().unwrap_or(""),
                    record.seq.map(|s| s.to_string()).unwrap_or_default(),
                    record.ack.map(|a| a.to_string()).unwrap_or_default(),
                )?;
            }
            RecordFormat::Json => {
                if self.records_written > 0 {
                    write!(self.writer, ",")?;
                }
                writeln!(self.writer, "{}", serde_json::to_string(record)?)?;
            }
            RecordFormat::JsonLines => {
                writeln!(self.writer, "{}", serde_json::to_string(record)?)?;
            }
        }

        self.records_written += 1;
        Ok(())
    }

    /// Write multiple records
    pub fn write_batch(&mut self, records: &[PacketRecord]) -> anyhow::Result<()> {
        for record in records {
            self.write(record)?;
        }
        Ok(())
    }

    /// Flush and finalize
    pub fn finish(mut self) -> anyhow::Result<u64> {
        if matches!(self.format, RecordFormat::Json) {
            writeln!(self.writer, "]")?;
        }
        self.writer.flush()?;
        Ok(self.records_written)
    }

    /// Get records written so far
    pub fn records_written(&self) -> u64 {
        self.records_written
    }
}

/// Summary statistics for the attack session
#[derive(Debug, Clone, Serialize)]
pub struct SessionSummary {
    /// Start time
    pub start_time: chrono::DateTime<Utc>,
    /// End time
    pub end_time: chrono::DateTime<Utc>,
    /// Duration in seconds
    pub duration_secs: f64,
    /// Total packets generated
    pub total_packets: u64,
    /// Packets per second
    pub packets_per_second: f64,
    /// Breakdown by attack type
    pub by_attack_type: std::collections::HashMap<String, u64>,
    /// Target IP
    pub target: String,
    /// Source IP
    pub source: String,
}

impl SessionSummary {
    pub fn new(
        start_time: chrono::DateTime<Utc>,
        total_packets: u64,
        by_attack_type: std::collections::HashMap<String, u64>,
        target: String,
        source: String,
    ) -> Self {
        let end_time = Utc::now();
        let duration_secs = (end_time - start_time).num_milliseconds() as f64 / 1000.0;
        let packets_per_second = if duration_secs > 0.0 {
            total_packets as f64 / duration_secs
        } else {
            0.0
        };

        Self {
            start_time,
            end_time,
            duration_secs,
            total_packets,
            packets_per_second,
            by_attack_type,
            target,
            source,
        }
    }

    /// Write summary to file
    pub fn write_to_file(&self, path: &Path) -> anyhow::Result<()> {
        let file = File::create(path)?;
        serde_json::to_writer_pretty(file, self)?;
        Ok(())
    }
}

/// Attack type statistics
#[derive(Debug, Clone, Default)]
pub struct AttackStats {
    counts: std::collections::HashMap<AttackType, u64>,
}

impl AttackStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment(&mut self, attack_type: AttackType) {
        *self.counts.entry(attack_type).or_insert(0) += 1;
    }

    pub fn add(&mut self, attack_type: AttackType, count: u64) {
        *self.counts.entry(attack_type).or_insert(0) += count;
    }

    pub fn total(&self) -> u64 {
        self.counts.values().sum()
    }

    pub fn to_string_map(&self) -> std::collections::HashMap<String, u64> {
        self.counts.iter()
            .map(|(k, v)| (k.to_string(), *v))
            .collect()
    }

    pub fn print_summary(&self) {
        println!("\nAttack Distribution:");
        println!("{:-<50}", "");

        let mut sorted: Vec<_> = self.counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(a.1));

        let total = self.total() as f64;
        for (attack_type, count) in sorted {
            let pct = (*count as f64 / total) * 100.0;
            println!("  {:25} {:>10} ({:5.1}%)", attack_type.to_string(), count, pct);
        }

        println!("{:-<50}", "");
        println!("  {:25} {:>10}", "TOTAL", self.total());
    }
}
