use mtp::client::MTPConnection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::{Duration, Instant};

use crate::metrics::PipeResult;

pub async fn run_pipe_demo(
    conn: &MTPConnection,
    iterations: usize,
) -> Result<Vec<PipeResult>, Box<dyn std::error::Error>> {
    let sizes = [64, 256, 1024, 4096];
    let mut all_elapsed = Vec::with_capacity(sizes.len() * iterations);
    let mut all_data_only = Vec::with_capacity(sizes.len() * iterations);
    let mut pipe_results = Vec::with_capacity(sizes.len() * iterations);

    for (i, &size) in sizes.iter().enumerate() {
        let mut size_elapsed = Vec::with_capacity(iterations);
        let mut size_data_only = Vec::with_capacity(iterations);

        for run in 0..iterations {
            let random_bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
            let description = format!("pipe-demo-{i}-run{run}");
            println!("  [pipe {i}.{run}] creating pipe ({size} bytes): {description}");

            let handle = conn.create_pipe(&description).await?;
            let pipe_id = handle.pipe_id_value();
            println!("  [pipe {i}.{run}] create_pipe returned (pipe_id={pipe_id})");

            // Overall timer starts before any I/O
            let overall_start = Instant::now();

            // Channel to capture the instant the writer actually starts writing
            let (write_start_tx, write_start_rx) = oneshot::channel();

            let write_bytes = random_bytes.clone();
            let writer_handle = tokio::spawn(async move {
                println!("  [pipe {i}.{run}] writer: waiting for server accept ...");
                match handle.wait().await {
                    Ok(Some(mut writer)) => {
                        // Record the instant we begin writing
                        let _ = write_start_tx.send(Instant::now());

                        println!(
                            "  [pipe {i}.{run}] writer: pipe accepted (pipe_id={pipe_id}), writing {} bytes ...",
                            write_bytes.len()
                        );
                        writer
                            .write_all(&write_bytes)
                            .await
                            .map_err(|e| mtp::common::PipeError::IoError(e.to_string()))?;
                        writer
                            .finish()
                            .await
                            .map_err(|e| mtp::common::PipeError::IoError(e.to_string()))?;
                        Ok::<(), mtp::common::PipeError>(())
                    }
                    Ok(None) => {
                        eprintln!("  [pipe {i}.{run}] writer: pipe denied by server");
                        Err(mtp::common::PipeError::Rejected)
                    }
                    Err(e) => {
                        eprintln!("  [pipe {i}.{run}] writer: error: {e}");
                        Err(e)
                    }
                }
            });

            println!("  [pipe {i}.{run}] waiting for server's return pipe via receive_pipe() ...");
            let pipe_req = conn.receive_pipe().await?;
            println!(
                "  [pipe {i}.{run}] received return pipe: id={} desc={:?}",
                pipe_req.id(),
                pipe_req.description()
            );

            let mut reader = pipe_req.accept().await?;
            println!("  [pipe {i}.{run}] return pipe accepted, reading data ...");

            let mut buf = Vec::new();
            reader.read_to_end(&mut buf).await?;
            let overall_elapsed = overall_start.elapsed();

            // Receive the instant the writer started writing
            let data_start = write_start_rx.await?;
            let data_only_elapsed = Instant::now() - data_start;

            match writer_handle.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => eprintln!("  [pipe {i}.{run}] writer error: {e}"),
                Err(e) => eprintln!("  [pipe {i}.{run}] writer task panicked: {e}"),
            }

            let matches = buf == random_bytes;
            println!(
                "  [pipe {i}.{run}] round-trip: {} bytes, \
                 total={:.3}ms, data-only={:.3}ms, match={matches}",
                size,
                overall_elapsed.as_secs_f64() * 1000.0,
                data_only_elapsed.as_secs_f64() * 1000.0,
            );

            pipe_results.push(PipeResult {
                size,
                iteration: run,
                total_ms: overall_elapsed.as_secs_f64() * 1000.0,
                data_only_ms: data_only_elapsed.as_secs_f64() * 1000.0,
                bytes_matched: matches,
            });

            size_elapsed.push(overall_elapsed);
            size_data_only.push(data_only_elapsed);
            all_elapsed.push(overall_elapsed);
            all_data_only.push(data_only_elapsed);
        }

        // ---- per-size averages ----
        let avg_total = average_duration(&size_elapsed);
        let avg_data = average_duration(&size_data_only);
        println!(
            "  [pipe {i}] AVERAGE for size {size}: \
             total={avg_total:.3}ms, data-only={avg_data:.3}ms \
             (over {iterations} runs)"
        );
    }

    // ---- overall averages ----
    let overall_total = average_duration(&all_elapsed);
    let overall_data = average_duration(&all_data_only);
    println!(
        "  [summary] OVERALL AVERAGE loopback time: \
         total={overall_total:.3}ms, data-only={overall_data:.3}ms \
         ({} measurements)",
        all_elapsed.len()
    );

    Ok(pipe_results)
}

/// Helper: average a slice of Durations without overflowing.
fn average_duration(durations: &[Duration]) -> f64 {
    if durations.is_empty() {
        return 0.0;
    }
    let sum_ms: f64 = durations.iter().map(|d| d.as_secs_f64() * 1000.0).sum();
    sum_ms / durations.len() as f64
}
