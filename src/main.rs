use clap::error::ErrorKind;
use wand_cli::{Cli, Error, OutputFormat, run};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let cli = match Cli::try_parse_friendly() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            print!("{error}");
            return;
        }
        Err(error) => {
            let format = OutputFormat::from_process_args();
            eprintln!("{}", format.render_error(&Error::Input(error.to_string())));
            std::process::exit(2);
        }
    };
    let output = cli.output;
    if let Err(error) = run(cli).await {
        eprintln!("{}", output.render_error(&error));
        std::process::exit(error.exit_code());
    }
}
