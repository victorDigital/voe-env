use super::*;

pub(super) struct OperationProgress(ProgressBar);

impl OperationProgress {
    pub fn new(options: &Options, message: &'static str) -> Result<Self> {
        let mut frames: Vec<_> = (0..23)
            .map(|position| format!("{}=>{}", "-".repeat(position), "-".repeat(22 - position)))
            .collect();
        frames.push(frames[0].clone());
        let bar = progress_bar(options, None, "{msg} [{spinner}] {elapsed}")?
            .with_style(
                ProgressStyle::with_template("{msg} [{spinner}] {elapsed}")?
                    .tick_strings(&frames.iter().map(String::as_str).collect::<Vec<_>>()),
            )
            .with_message(message);
        bar.enable_steady_tick(Duration::from_millis(100));
        Ok(Self(bar))
    }
}

impl Drop for OperationProgress {
    fn drop(&mut self) {
        self.0.finish_and_clear();
    }
}

pub(super) fn progress_bar(
    options: &Options,
    length: Option<u64>,
    template: &str,
) -> Result<ProgressBar> {
    let target = if io::stdout().is_terminal()
        && io::stderr().is_terminal()
        && !options.json
        && !options.quiet
    {
        ProgressDrawTarget::stderr_with_hz(10)
    } else {
        ProgressDrawTarget::hidden()
    };
    Ok(ProgressBar::with_draw_target(length, target)
        .with_style(ProgressStyle::with_template(template)?.progress_chars("=>-"))
        .with_finish(ProgressFinish::AndClear))
}
