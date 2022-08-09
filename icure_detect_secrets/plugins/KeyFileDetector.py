from typing import Generator, Any, Set
import hashlib

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.util.code_snippet import CodeSnippet


_key_file_postfixes = {
    ".key",
    ".privkey",
    ".privKey"
}


class KeyFileDetector(BasePlugin):
    """
    Scan for .key filenames
    """

    @property
    def secret_type(self) -> str:
        return "Key file name"

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
        if KeyFileDetector.__is_key_filename(filename):
            return {PotentialSecret(self.secret_type, filename, _hash_file(filename))}
        else:
            return set()

    @staticmethod
    def __is_key_filename(filename) -> bool:
        for postfix in _key_file_postfixes:
            if filename.endswith(postfix):
                return True
        return False


def _hash_file(filename: str) -> str:
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        while True:
            data = f.read(65536)  # 64kb
            if not data:
                break
            md5.update(data)
    return md5.hexdigest()
