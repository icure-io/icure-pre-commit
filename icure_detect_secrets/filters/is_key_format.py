__token_formats = {
    'jwk',
    'pkcs8',
    'spki'
}


def is_key_format(secret: str) -> bool:
    return secret in __token_formats
