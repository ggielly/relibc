use crate::{error::Result, fs::File, header::fcntl, io::BufWriter};

use super::logger::LogSink;

/// Write logs to Strat9-OS's log facility.
pub struct LogFile(BufWriter<File>);

impl LogSink for LogFile {
    type Sink = BufWriter<File>;

    #[inline(always)]
    fn open() -> Result<Self> {
        // In Strat9-OS, we'll write logs to a special logging endpoint
        // For now, we'll use a placeholder path - this would be replaced with
        // actual Strat9-OS logging mechanism
        File::open(c"/log".into(), fcntl::O_WRONLY).map(|file| Self(BufWriter::new(file)))
    }

    #[inline(always)]
    fn writer(&mut self) -> &mut Self::Sink {
        &mut self.0
    }
}