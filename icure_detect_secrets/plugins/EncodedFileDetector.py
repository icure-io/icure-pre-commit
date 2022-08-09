from re import fullmatch, compile
from typing import Generator, Any, Set
import hashlib

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.util.code_snippet import CodeSnippet


_encode_patterns = list(map(
    lambda x: compile(x, flags=0),
    {
        r'[0-9a-f]+\s*',  # Hex all lowercase
        r'[0-9A-F]+\s*',  # Hex all uppercase
        r'[A-Za-z0-9+/]+=*\s*',  # Base64
        r'[A-Za-z0-9_\-]+\s*',  # Base64 url
    },
))


class EncodedFileDetector(BasePlugin):
    """
    Scan for files which as content have only hexadecimal lines
    """

    @property
    def secret_type(self) -> str:
        return "Fully encoded file (hex, base64, or other)"

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        yield from []

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        **kwargs: Any
    ) -> Set[PotentialSecret]:
        if line_number == 1 and EncodedFileDetector.has_only_encoded_lines(filename):
            return {PotentialSecret(self.secret_type, filename, _hash_file(filename))}
        else:
            set()

    @staticmethod
    def has_only_encoded_lines(filename: str) -> bool:
        had_non_empty = False
        valid_patterns = _encode_patterns
        with open(filename, 'r') as file:
            for line in file:
                if line and line.strip():
                    had_non_empty = True
                    valid_patterns = [
                        pattern for pattern in valid_patterns
                        if fullmatch(pattern, line) is not None
                    ]
                if len(valid_patterns) == 0:
                    return False
        return had_non_empty


def _hash_file(filename: str) -> str:
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(65536)  # 64kb
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()
