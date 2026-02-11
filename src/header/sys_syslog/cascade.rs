use crate::{error::Result, fs::File, header::fcntl, io::BufWriter};

use super::logger::LogSink;

/// Write logs to CascadeOS's log facility.
pub struct LogFile(BufWriter<File>);

impl LogSink for LogFile {
    type Sink = BufWriter<File>;

    #[inline(always)]
    fn open() -> Result<Self> {
        // In CascadeOS, we'll write logs to a special logging endpoint
        // For now, we'll use a placeholder path - this would be replaced with
        // actual CascadeOS logging mechanism
        File::open(c"/log".into(), fcntl::O_WRONLY).map(|file| Self(BufWriter::new(file)))
    }

    #[inline(always)]
    fn writer(&mut self) -> &mut Self::Sink {
        &mut self.0
    }
}