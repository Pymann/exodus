from typing import Any, Iterable


TypeKind: Any
CursorKind: Any
LinkageKind: Any
StorageClass: Any
AccessSpecifier: Any


class File:
    name: str


class SourceLocation:
    file: File | None
    line: int
    column: int
    offset: int
    is_in_system_header: bool


class SourceRangeEndpoint:
    line: int
    column: int
    offset: int


class SourceRange:
    start: SourceRangeEndpoint
    end: SourceRangeEndpoint


class Type:
    kind: Any
    spelling: str

    def get_canonical(self) -> Type: ...
    def is_const_qualified(self) -> bool: ...
    def is_volatile_qualified(self) -> bool: ...
    def get_pointee(self) -> Type: ...
    def get_declaration(self) -> Cursor: ...


class Token:
    spelling: str
    extent: SourceRange


class Cursor:
    kind: Any
    spelling: str
    semantic_parent: Cursor | None
    lexical_parent: Cursor | None
    referenced: Cursor | None
    location: SourceLocation
    extent: SourceRange
    type: Type
    result_type: Type
    linkage: Any
    storage_class: Any
    hash: int

    def get_tokens(self) -> Iterable[Token]: ...
    def get_children(self) -> Iterable[Cursor]: ...
    def walk_preorder(self) -> Iterable[Cursor]: ...
    def get_arguments(self) -> Iterable[Cursor] | None: ...
    def is_definition(self) -> bool: ...
    def get_usr(self) -> str: ...
    def is_virtual_base(self) -> bool: ...
    def is_abstract_record(self) -> bool: ...
    def is_virtual_method(self) -> bool: ...
    def is_const_method(self) -> bool: ...
    def is_pure_virtual_method(self) -> bool: ...
    def is_bitfield(self) -> bool: ...
    def get_bitfield_width(self) -> int: ...


class TranslationUnit:
    PARSE_DETAILED_PROCESSING_RECORD: int
    cursor: Cursor
    diagnostics: Iterable[Any]


class Index:
    @staticmethod
    def create() -> Index: ...
    def parse(
        self, path: str, args: list[str] | None = ..., options: int = ...
    ) -> TranslationUnit: ...


class Config:
    @staticmethod
    def set_library_file(filename: str) -> None: ...
