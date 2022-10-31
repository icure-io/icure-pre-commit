import re
from typing import Any
from typing import Dict
from typing import Generator
from typing import Optional
from typing import Pattern
from typing import Set
from typing import Sequence
from typing import List
from typing import Tuple
from enum import Enum
from abc import ABC, abstractmethod

from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.util.filetype import determine_file_type
from detect_secrets.util.filetype import FileType
from detect_secrets.plugins.base import BasePlugin
from detect_secrets.util.code_snippet import CodeSnippet

"""
Class sensitive regex provider, gives allowed string literal quotes as a list of characters and if it needs to be the
"reversed" version, returns a regex for keyword and regex for sensitive value.
Each of the full regexes which before were unique is now not.
"""


# Regex to represent a proper name value, such as a person or city name.
# Includes special letters with accent, umlaut, and some common punctuation symbols which can appear in names.
# Does not match any numbers, so we won't detect if we are about to leak "X AE A-12"'s personal details.
PROPER_NAME_NO_ESCAPE_STRING_CONTENT_REGEX = r"[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF '`\.]+"
PROPER_NAME_SINGLE_QUOTE_STRING_REGEX = r"'(?:[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF `\.]|\\')+'"
# No escaped double quote as double quote should not appear in names
PROPER_NAME_BACKTICK_STRING_REGEX = r"`(?:[a-zA-Z\u00C0-\u024F\u1E00-\u1EFF '\.]|\\`)+`"
# Keywords which may contain sensitive data if associated to a proper name value
PROPER_NAME_KEYWORDS = [
    'lastName',
    'firstName',
    'maidenName',
    'spouseName',
    'partnerName',
    'placeOfBirth',
    'nationality',
    'nativeCountry',
    'birthCountry',
    'fatherBirthCountry',
]

# Matches hexadecimal strings or base64 strings
ENCODED_DATA_STRING_CONTENT_REGEX = r"[a-zA-Z0-9]+\={0,2}"
# Keywords which may contain sensitive data if associated to encoded data value
ENCODED_DATA_KEYWORDS = [
    'enckeys',
    'picture',
]

# Matches date string
DATE_DATA_STRING_CONTENT_REGEX = r"[0-9]{2}/[0-9]{2}/[0-9]{2}(?:[0-9]{2})?|[0-9]{4}/[0-9]{2}/[0-9]{2}|[0-9]{6}(?:[0-9]{2})?"
# Keywords which may contain sensitive data if associated to
DATE_DATA_KEYWORDS = [
    'dateOfBirth'
]

# Keywords which may contain sensitive data if associated to a list literal
LIST_DATA_KEYWORDS = [
    'addresses'
]


class StringQuoteType(Enum):
    NONE = 1,
    SINGLE = 2,
    DOUBLE = 3,
    BACK = 4


class SensitiveDataRegexProvider(ABC):
    def keywords_regex(self) -> str:
        joined = r'|'.join(self.keywords())
        return r"(?:{joined})".format(joined=joined)

    @abstractmethod
    def keywords(self) -> Sequence[str]:
        pass

    @abstractmethod
    def value_regex(self, left_side: bool, quote_types: Set[StringQuoteType]) -> str:
        """
        Regex to detect the value of the sensitive data, including the quote symbol
        :param left_side: true if the value will appear on the left side of a comparison
        :param quote_types: type of quotes used to represent strings in the current file type
        :return: a regex to represent a possible value for the sensitive data. If the possible value is a string type
        it must include the quotes.
        """
        pass


def regex_quoted_string_content(quote_type: StringQuoteType, string_content_regex: str) -> str:
    if quote_type == StringQuoteType.NONE:
        wrapped_content_pattern = r"{content}"
    elif quote_type == StringQuoteType.BACK:
        wrapped_content_pattern = r"`{content}`"
    elif quote_type == StringQuoteType.SINGLE:
        wrapped_content_pattern = r"'{content}'"
    elif quote_type == StringQuoteType.DOUBLE:
        wrapped_content_pattern = r'"{content}"'
    else:
        raise Exception(f"Unexpected string quote type {quote_type}")
    return wrapped_content_pattern.format(content=string_content_regex)


def regex_all_quoted_string_content(
    quote_types: Set[StringQuoteType],
    string_content_regex: str
):
    return r'|'.join([regex_quoted_string_content(quote_type, string_content_regex) for quote_type in quote_types])


class ProperNameRegexProvider(SensitiveDataRegexProvider):
    """
    Sensitive data regex provider for proper names (e.g. person or city names)
    """

    def keywords(self) -> Sequence[str]:
        return PROPER_NAME_KEYWORDS

    def value_regex(self, left_side: bool, quote_types: Set[StringQuoteType]) -> str:
        return r'|'.join([ProperNameRegexProvider.quoted_regex(quote_type) for quote_type in quote_types])

    @staticmethod
    def quoted_regex(quote_type: StringQuoteType) -> str:
        if quote_type == StringQuoteType.SINGLE:
            return PROPER_NAME_SINGLE_QUOTE_STRING_REGEX
        elif quote_type == StringQuoteType.BACK:
            return PROPER_NAME_BACKTICK_STRING_REGEX
        else:
            return regex_quoted_string_content(quote_type, PROPER_NAME_NO_ESCAPE_STRING_CONTENT_REGEX)


class EncodedDataRegexProvider(SensitiveDataRegexProvider):
    """
    Sensitive data regex provider for fields with encoded data
    """

    def keywords(self) -> Sequence[str]:
        return ENCODED_DATA_KEYWORDS

    def value_regex(self, left_side: bool, quote_types: Set[StringQuoteType]) -> str:
        return regex_all_quoted_string_content(quote_types, ENCODED_DATA_STRING_CONTENT_REGEX)


class DateDataRegexProvider(SensitiveDataRegexProvider):
    """
    Sensitive data regex provider for fields with date values
    """

    def keywords(self) -> Sequence[str]:
        return DATE_DATA_KEYWORDS

    def value_regex(self, left_side: bool, quote_types: Set[StringQuoteType]) -> str:
        date_string = regex_all_quoted_string_content(quote_types, DATE_DATA_STRING_CONTENT_REGEX)
        date_number = r"[0-9]{8}"
        return r"{date_string}|{date_number}".format(
            date_string=date_string,
            date_number=date_number
        )


# TODO not trivial to figure out the secret for lists
# class ListDataRegexProvider(SensitiveDataRegexProvider):
#     """
#     Sensitive data regex provider for fields with list values
#     """
#
#     def keywords(self) -> Sequence[str]:
#         return LIST_DATA_KEYWORDS
#
#     def value_regex(self, left_side: bool, quote_types: Set[StringQuoteType]) -> str:
#         if left_side:
#             return r"\]"
#         else:
#             return r"\["


class SsinRegexProvider(SensitiveDataRegexProvider):
    """
    Sensitive data regex provider for ssin
    """

    def keywords(self) -> Sequence[str]:
        return ["ssin"]

    def value_regex(self, left_side: bool, quote_types: Set[StringQuoteType]) -> str:
        return regex_all_quoted_string_content(
            quote_types,
            r"[0-9]{11}|[0-9]{2}\.[0-9]{2}\.[0-9]{2}-[0-9]{3}\.[0-9]{2}"
        )


# Based on https://github.com/Yelp/detect-secrets/blob/88a3fc1b382403c43cda98a9a512a4f6e12b8687/detect_secrets/plugins/keyword.py  # noqa: 501
# Includes ], ', " as closing
CLOSING = r'[]\'"]{0,2}'
AFFIX_REGEX = r'\w*'
# Non-greedy match
OPTIONAL_WHITESPACE = r'\s*'
OPTIONAL_NON_WHITESPACE = r'[^\s]{0,50}?'

SQUARE_BRACKETS = r'(?:\[[0-9]*\])'

OPTIONAL_QUOTES = {StringQuoteType.BACK, StringQuoteType.SINGLE, StringQuoteType.DOUBLE, StringQuoteType.NONE}
REQUIRED_QUOTES = {StringQuoteType.BACK, StringQuoteType.SINGLE, StringQuoteType.DOUBLE}


class SensitiveDataAssignmentRegexProvider(ABC):
    """
    Provides regex to detect assignments of sensitive data
    """
    def secret_group(self) -> int:
        return 1

    @abstractmethod
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        pass


class FollowedByColonEqualSigns(SensitiveDataAssignmentRegexProvider):
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, OPTIONAL_QUOTES)
        return re.compile(
            r'{name}(?:{closing})?{whitespace}:=?{whitespace}({secret})'.format(
                name=name,
                closing=CLOSING,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret
            )
        )


class FollowedByColon(SensitiveDataAssignmentRegexProvider):
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, OPTIONAL_QUOTES)
        return re.compile(
            r'{name}(?:{closing})?:{whitespace}({secret})'.format(
                name=name,
                closing=CLOSING,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret
            )
        )


class FollowedByColonQuotesRequired(SensitiveDataAssignmentRegexProvider):
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, REQUIRED_QUOTES)
        return re.compile(
            r'{name}(?:{closing})?:{whitespace}({secret})'.format(
                name=name,
                closing=CLOSING,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret
            )
        )


class FollowedByEqualSignsOptionalBraketsOptionalAtSignQuotesRequired(SensitiveDataAssignmentRegexProvider):
    # e.g. my_password = "bar"
    # e.g. my_password = @"bar"
    # e.g. my_password[] = "bar";
    # e.g. char my_password[25] = "bar";

    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, {StringQuoteType.DOUBLE})
        return re.compile(
            r'{name}(?:{square_brackets})?{optional_whitespace}[!=]{{1,2}}{optional_whitespace}@?({secret})'.format(  # noqa: E501
                name=name,
                square_brackets=SQUARE_BRACKETS,
                optional_whitespace=OPTIONAL_WHITESPACE,
                secret=secret
            )
        )


class FollowedByOptionalAssignQuotesRequired(SensitiveDataAssignmentRegexProvider):
    # e.g. std::string secret("bar");
    # e.g. secret.assign("bar",17);
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, {StringQuoteType.DOUBLE})
        return re.compile(
            r'{name}(?:.assign)?\(({secret})'.format(
                name=name,
                secret=secret,
            )
        )


class FollowedByEqualSigns(SensitiveDataAssignmentRegexProvider):
    # e.g. my_password = bar
    # e.g. my_password == "bar" or my_password != "bar" or my_password === "bar"
    # or my_password !== "bar"
    # e.g. my_password == 'bar' or my_password != 'bar' or my_password === 'bar'
    # or my_password !== 'bar'
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, OPTIONAL_QUOTES)
        return re.compile(
            r'{name}(?:{closing})?{whitespace}(?:={{1,3}}|!==?){whitespace}({secret})'.format(  # noqa: E501
                name=name,
                closing=CLOSING,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret,
            )
        )

class FollowedByEqualSignsQuotesRequired(SensitiveDataAssignmentRegexProvider):
    # e.g. my_password = "bar"
    # e.g. my_password == "bar" or my_password != "bar" or my_password === "bar"
    # or my_password !== "bar"
    # e.g. my_password == 'bar' or my_password != 'bar' or my_password === 'bar'
    # or my_password !== 'bar'
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, REQUIRED_QUOTES)
        return re.compile(
            r'{name}(?:{closing})?{whitespace}(?:={{1,3}}|!==?){whitespace}({secret})'.format(  # noqa: E501
                name=name,
                closing=CLOSING,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret,
            )
        )


class PrecededByEqualComparisonSignsQuotesRequired(SensitiveDataAssignmentRegexProvider):
    # e.g. "bar" == my_password or "bar" != my_password or "bar" === my_password
    # or "bar" !== my_password
    # e.g. 'bar' == my_password or 'bar' != my_password or 'bar' === my_password
    # or 'bar' !== my_password
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, REQUIRED_QUOTES)
        return re.compile(
            r'({secret}){whitespace}[!=]{{2,3}}{whitespace}{name}'.format(
                name=name,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret,
            ),
        )


class FollowedByQuotesAndSemicolon(SensitiveDataAssignmentRegexProvider):
    # e.g. private_key "bar";
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, REQUIRED_QUOTES)
        return re.compile(
            r'{name}{nonWhitespace}{whitespace}({secret});'.format(
                name=name,
                nonWhitespace=OPTIONAL_NON_WHITESPACE,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret,
            )
        )


class FollowedByArrowFunctionSignQuotesRequired(SensitiveDataAssignmentRegexProvider):
    # e.g. my_password => "bar" or my_password => bar
    def compile(self, sdrp: SensitiveDataRegexProvider) -> Pattern:
        name = sdrp.keywords_regex()
        secret = sdrp.value_regex(False, REQUIRED_QUOTES)
        return re.compile(
            r'{name}(?:{closing})?{whitespace}=>?{whitespace}({secret})'.format(
                name=name,
                closing=CLOSING,
                whitespace=OPTIONAL_WHITESPACE,
                secret=secret,
            )
        )


FOLLOWED_BY_COLON = FollowedByColon()
PRECEDED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED = PrecededByEqualComparisonSignsQuotesRequired()
FOLLOWED_BY_EQUAL_SIGNS = FollowedByEqualSigns()
FOLLOWED_BY_QUOTES_AND_SEMICOLON = FollowedByQuotesAndSemicolon()
FOLLOWED_BY_COLON_EQUAL_SIGNS = FollowedByColonEqualSigns()
FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS_OPTIONAL_AT_SIGN_QUOTES_REQUIRED = FollowedByEqualSignsOptionalBraketsOptionalAtSignQuotesRequired()
FOLLOWED_BY_COLON_QUOTES_REQUIRED = FollowedByColonQuotesRequired()
FOLLOWED_BY_OPTIONAL_ASSIGN_QUOTES_REQUIRED = FollowedByOptionalAssignQuotesRequired()
FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED = FollowedByEqualSignsQuotesRequired()
FOLLOWED_BY_ARROW_FUNCTION_SIGN_QUOTES_REQUIRED = FollowedByArrowFunctionSignQuotesRequired()

ALL_KEYWORD_CONTENT_PROVIDERS: Sequence[SensitiveDataRegexProvider] = [
    ProperNameRegexProvider(),
    EncodedDataRegexProvider(),
    DateDataRegexProvider(),
    SsinRegexProvider()
]

CONFIG_PROVIDERS: Sequence[SensitiveDataAssignmentRegexProvider] = [
    FOLLOWED_BY_COLON,
    PRECEDED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED,
    FOLLOWED_BY_EQUAL_SIGNS,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON,
]
GOLANG_PROVIDERS: Sequence[SensitiveDataAssignmentRegexProvider] = [
    FOLLOWED_BY_COLON_EQUAL_SIGNS,
    PRECEDED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED,
    FOLLOWED_BY_EQUAL_SIGNS,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON,
]
COMMON_C_PROVIDERS: Sequence[SensitiveDataAssignmentRegexProvider] = [
    FOLLOWED_BY_EQUAL_SIGNS_OPTIONAL_BRACKETS_OPTIONAL_AT_SIGN_QUOTES_REQUIRED,
]
C_PLUS_PLUS_PROVIDERS: Sequence[SensitiveDataAssignmentRegexProvider] = [
    FOLLOWED_BY_OPTIONAL_ASSIGN_QUOTES_REQUIRED,
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED,
]
QUOTES_REQUIRED_PROVIDERS: Sequence[SensitiveDataAssignmentRegexProvider] = [
    FOLLOWED_BY_COLON_QUOTES_REQUIRED,
    PRECEDED_BY_EQUAL_COMPARISON_SIGNS_QUOTES_REQUIRED,
    FOLLOWED_BY_EQUAL_SIGNS_QUOTES_REQUIRED,
    FOLLOWED_BY_QUOTES_AND_SEMICOLON,
    FOLLOWED_BY_ARROW_FUNCTION_SIGN_QUOTES_REQUIRED,
]
PROVIDERS_BY_FILETYPE: Dict[FileType, Sequence[SensitiveDataAssignmentRegexProvider]] = {
    FileType.GO: GOLANG_PROVIDERS,
    FileType.OBJECTIVE_C: COMMON_C_PROVIDERS,
    FileType.C_SHARP: COMMON_C_PROVIDERS,
    FileType.C: COMMON_C_PROVIDERS,
    FileType.C_PLUS_PLUS: C_PLUS_PLUS_PROVIDERS,
    FileType.CLS: QUOTES_REQUIRED_PROVIDERS,
    FileType.JAVA: QUOTES_REQUIRED_PROVIDERS,
    FileType.JAVASCRIPT: QUOTES_REQUIRED_PROVIDERS,
    FileType.PYTHON: QUOTES_REQUIRED_PROVIDERS,
    FileType.SWIFT: QUOTES_REQUIRED_PROVIDERS,
    FileType.TERRAFORM: QUOTES_REQUIRED_PROVIDERS,
    FileType.YAML: CONFIG_PROVIDERS,
    FileType.CONFIG: CONFIG_PROVIDERS,
    FileType.INI: CONFIG_PROVIDERS,
    FileType.PROPERTIES: CONFIG_PROVIDERS,
    FileType.TOML: CONFIG_PROVIDERS,
    FileType.OTHER: QUOTES_REQUIRED_PROVIDERS
}


def combine(assignments: Sequence[SensitiveDataAssignmentRegexProvider], keywords: Sequence[SensitiveDataRegexProvider]) -> Sequence[Tuple[Pattern, int]]:
    res: List[Tuple[Pattern, int]] = []
    for a in assignments:
        for b in keywords:
            res.append((a.compile(b), a.secret_group()))
    return res


REGEXES_WITH_GROUP_BY_FILETYPE: Dict[FileType, Sequence[Tuple[Pattern, int]]] = {
    filetype: combine(providers, ALL_KEYWORD_CONTENT_PROVIDERS)
    for filetype, providers in PROVIDERS_BY_FILETYPE.items()
}


class IcureSensitiveKeywordDetector(BasePlugin):
    """
    Scans for sensitive variables.
    """
    secret_type = 'ICure Sensitive Keyword' # pragma: allowlist secret

    def analyze_string(
        self,
        string: str,
        regexes_to_group: Optional[Sequence[Tuple[Pattern, int]]] = None,
    ) -> Generator[str, None, None]:
        if regexes_to_group is None:
            regexes_to_group = REGEXES_WITH_GROUP_BY_FILETYPE[FileType.OTHER]

        for denylist_regex, group_number in regexes_to_group:
            match = denylist_regex.search(string)
            if match:
                print("It's a match")
                print(string)
                print(match.group(group_number))
                yield match.group(group_number)

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        filetype = determine_file_type(filename)
        regexes_to_group = REGEXES_WITH_GROUP_BY_FILETYPE.get(filetype, QUOTES_REQUIRED_PROVIDERS)
        return super().analyze_line(
            filename=filename,
            line=line,
            line_number=line_number,
            context=context,
            regexes_to_group=regexes_to_group,
        )
