
from app.forensics.signatures import identify
def test_pdf(): assert identify(b"%PDF-1.7").extension==".pdf"
def test_zip(): assert identify(b"PK\x03\x04").extension==".zip"
def test_text(): assert identify(b"hello\nworld").extension==".txt"
