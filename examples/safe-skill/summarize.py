"""Extract plain text from a PDF the user named, nothing else."""

from pathlib import Path


def extract_text(pdf_path):
    """Return the text of a PDF as a plain string."""
    path = Path(pdf_path)
    if not path.is_file():
        raise FileNotFoundError("no such file: %s" % pdf_path)
    if path.suffix.lower() != ".pdf":
        raise ValueError("expected a .pdf file, got %s" % path.suffix)
    data = path.read_bytes()
    chunks = []
    for part in data.split(b"stream"):
        try:
            chunks.append(part.decode("latin-1"))
        except UnicodeDecodeError:
            continue
    return "\n".join(chunks)
