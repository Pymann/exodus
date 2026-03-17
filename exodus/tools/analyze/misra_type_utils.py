from typing import Any

from clang.cindex import TypeKind


def is_integral_kind(kind: Any) -> bool:
    return kind in (
        TypeKind.BOOL,
        TypeKind.CHAR_U,
        TypeKind.UCHAR,
        TypeKind.CHAR16,
        TypeKind.CHAR32,
        TypeKind.USHORT,
        TypeKind.UINT,
        TypeKind.ULONG,
        TypeKind.ULONGLONG,
        TypeKind.UINT128,
        TypeKind.CHAR_S,
        TypeKind.SCHAR,
        TypeKind.WCHAR,
        TypeKind.SHORT,
        TypeKind.INT,
        TypeKind.LONG,
        TypeKind.LONGLONG,
        TypeKind.INT128,
        TypeKind.ENUM,
    )


def is_floating_kind(kind: Any) -> bool:
    return kind in (TypeKind.FLOAT, TypeKind.DOUBLE, TypeKind.LONGDOUBLE)


def is_unsigned_kind(kind: Any) -> bool:
    return kind in (
        TypeKind.CHAR_U,
        TypeKind.UCHAR,
        TypeKind.USHORT,
        TypeKind.UINT,
        TypeKind.ULONG,
        TypeKind.ULONGLONG,
        TypeKind.UINT128,
    )


def is_pointer_or_reference_kind(kind: Any) -> bool:
    return kind in (
        TypeKind.POINTER,
        TypeKind.LVALUEREFERENCE,
        TypeKind.RVALUEREFERENCE,
    )


def is_signed_integral_kind(kind: Any) -> bool:
    return kind in (
        TypeKind.CHAR_S,
        TypeKind.SCHAR,
        TypeKind.SHORT,
        TypeKind.INT,
        TypeKind.LONG,
        TypeKind.LONGLONG,
        TypeKind.INT128,
        TypeKind.WCHAR,
    )


def is_fundamental_kind(kind: Any) -> bool:
    return kind in (
        TypeKind.BOOL,
        TypeKind.CHAR_U,
        TypeKind.UCHAR,
        TypeKind.CHAR16,
        TypeKind.CHAR32,
        TypeKind.USHORT,
        TypeKind.UINT,
        TypeKind.ULONG,
        TypeKind.ULONGLONG,
        TypeKind.UINT128,
        TypeKind.CHAR_S,
        TypeKind.SCHAR,
        TypeKind.WCHAR,
        TypeKind.SHORT,
        TypeKind.INT,
        TypeKind.LONG,
        TypeKind.LONGLONG,
        TypeKind.INT128,
        TypeKind.FLOAT,
        TypeKind.DOUBLE,
        TypeKind.LONGDOUBLE,
    )
