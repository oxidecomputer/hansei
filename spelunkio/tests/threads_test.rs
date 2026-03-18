use anyhow::Result;

#[test]
fn test_threads_command() -> Result<()> {
    let home = std::env::var("HOME").expect("HOME not set");
    let core_path = format!("{home}/hansei-futurelock.core");
    let dbg = spelunkio::Dbg::new(
        core_path.into(),
        "../target/release/futurelock".into(),
    )?;
    let runtime = spelunkio::load_tokio_runtime(&dbg)?;
    let _ = spelunkio::dispatch_command(&runtime, &dbg, "threads")?;
    Ok(())
}

#[test]
fn test_tasks_command() -> Result<()> {
    let home = std::env::var("HOME").expect("HOME not set");
    let core_path = format!("{home}/hansei-futurelock.core");
    let dbg = spelunkio::Dbg::new(
        core_path.into(),
        "../target/release/futurelock".into(),
    )?;
    let runtime = spelunkio::load_tokio_runtime(&dbg)?;

    // Verify we have tasks
    assert!(
        !runtime.scheduler.shared.owned.tasks.is_empty(),
        "expected at least one task"
    );

    // Resolve the concrete type of each task
    for (addr, _header) in &runtime.scheduler.shared.owned.tasks {
        let concrete_type =
            hansei_types::tokio::dwarf::resolve_task_type(&dbg, *addr)?;
        // The futurelock program should have tasks with "futurelock" in the type
        println!("  {addr:?}: {concrete_type}");
        assert!(!concrete_type.is_empty());
    }

    // Run the tasks command to verify it doesn't error
    let _ = spelunkio::dispatch_command(&runtime, &dbg, "tasks")?;
    Ok(())
}

#[test]
fn test_task_trace() -> Result<()> {
    let home = std::env::var("HOME").expect("HOME not set");
    let core_path = format!("{home}/hansei-futurelock.core");
    let dbg = spelunkio::Dbg::new(
        core_path.into(),
        "../target/release/futurelock".into(),
    )?;
    let runtime = spelunkio::load_tokio_runtime(&dbg)?;

    // Find a task and get its ID
    let (_addr, header) =
        runtime.scheduler.shared.owned.tasks.iter().next().unwrap();
    let task_id = header.id;

    // Run the task-trace command
    let _ = spelunkio::dispatch_command(
        &runtime,
        &dbg,
        &format!("task-trace {task_id}"),
    )?;

    // Also verify the trace contains expected content
    let trace = hansei_types::tokio::dwarf::task_await_trace(&dbg, *_addr)?;
    assert!(
        trace.contains("futurelock"),
        "trace should mention futurelock: {trace}"
    );
    assert!(
        trace.contains("suspended"),
        "trace should show suspension: {trace}"
    );
    Ok(())
}
