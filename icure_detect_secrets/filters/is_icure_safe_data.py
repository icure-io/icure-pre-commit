from typing import Dict, Any, Union, Sequence, Optional, Set
from functools import lru_cache
import json


def is_icure_safe_data(filename: str, secret: str) -> bool:
    return secret in __extract_safe_data(filename)


@lru_cache(maxsize=1)
def __extract_safe_data(filename: str) -> Set[str]:
    parsed = __try_parse_json(filename)
    if parsed is None:
        return set()
    else:
        return __extract_recursively(parsed)


def __try_parse_json(filename: str) -> Optional[Union[Dict[Any, Any], Sequence[Dict[Any, Any]]]]:
    try:
        with open(filename, 'r') as file:
            return json.load(file)
    except json.JSONDecodeError:
        return None


def __extract_recursively(obj: Union[Dict[Any, Any], Sequence[Any]]) -> Set[str]:
    if isinstance(obj, dict):
        return __extract_one(obj)
    elif isinstance(obj, str):
        return set()
    elif isinstance(obj, Sequence):
        results: Set[str] = set()
        for item in obj:
            results = results.union(__extract_recursively(item))
        return results
    else:
        return set()


__crypted_keys_holders = {
    'cryptedForeignKeys',
    'delegations',
    'encryptionKeys'
}


# Keys of data string which should never be able to carry sensitive data
__safe_strings_keys = {
    'parent',
    'attachmentId',
    'objectStoreReference',
    'insuranceId',
    'layoutAttachmentId',
    'publicKey',
    'contract',
    'recipientIds',
    'digest'
}


def __extract_one(obj: Dict[str, Any]) -> Set[str]:
    results: Set[str] = set()
    for key, value in obj.items():
        if key in __crypted_keys_holders:
            results = results.union(__extract_crypted_keys(value))
        elif key == 'hcPartyKeys':
            results = results.union(__extract_hc_party_keys(value))
        elif key in __safe_strings_keys and isinstance(value, str):
            results.add(value)
        else:
            results = results.union(__extract_recursively(value))
    return results


def __extract_crypted_keys(cfk: Dict[str, Sequence[Dict[str, str]]]) -> Set[str]:
    results: Set[str] = set()
    for user_keys in cfk.values():
        for key_info in user_keys:
            if 'key' in key_info:
                results.add(key_info['key'])
    return results


def __extract_hc_party_keys(hcpk: Dict[str, Sequence[str]]) -> Set[str]:
    results: Set[str] = set()
    for keys in hcpk.values():
        results = results.union(keys)
    return results
