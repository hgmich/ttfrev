#!/usr/bin/env python3
import logging

log = logging.Logger(__package__ or "cbin")

from dataclasses import dataclass
import enum
from construct import (
    Bytes,
    Rebuild,
    Const,
    Int32ul,
    Int32sl,
    this,
    Hex,
    Pointer,
    len_,
    Computed,
    Check,
    Array,
    CString,
    Float32l,
    IfThenElse,
    RestreamData,
)
from construct.core import possiblestringencodings
from construct_typed import DataclassMixin, DataclassStruct, csfield, TEnum, EnumBase
from typing import Any, Union, Optional

from collections import OrderedDict
import json
import itertools

from .common import XorCrypted


# Force construct to support ISO-8859-1 encoding for CString
possiblestringencodings["iso_8859_1"] = 1


@dataclass
class CBINHeader(DataclassMixin):
    signature: bytes = csfield(Const(b"CBIN"))
    string_table_offset: int = csfield(Hex(Int32ul))
    string_table_length: int = csfield(Rebuild(Hex(Int32ul), lambda this: this._root.data.string_table.sizeof()))
    string_table_count: int = csfield(Rebuild(Int32ul, len_(this._root.data.string_table)))
    xor_key: int = csfield(Hex(Int32ul))


@dataclass
class CBINLabel(DataclassMixin):
    _str_id: int = csfield(Int32ul)
    name: str = csfield(Computed(lambda this: this._._string_table[this._str_id - 1] if this._str_id != 0 else None))
    num_ents: int = csfield(Int32ul)


@dataclass
class CBINEntry(DataclassMixin):
    _str_id: int = csfield(Int32ul)
    name: Optional[str] = csfield(Computed(lambda this: this._._string_table[this._str_id - 1] if this._str_id != 0 else None))
    num_vals: int = csfield(Int32ul)

    @property
    def is_nil(self):
        return self.name is None and self.num_vals == 0


class ValueType(EnumBase):
    INT = 1
    FLOAT = 2
    STRING = 4


def convert_value(this) -> Union[str, int, float]:
    if this.type == ValueType.STRING:
        val: str | None = this._._string_table[this._val - 1] if this._val != 0 else None
        if val is None:
            raise IndexError(f"Missing string index {this._val}")
        return val
    elif this.type == ValueType.FLOAT:
        # Truncate to sidestep 32-bit float epsilon issues due to python-forced
        # upconvert to f64
        return float(f"{this._val:.7g}")
    else:
        return this._val


@dataclass
class CBINValue(DataclassMixin):
    val_bytes: bytes = csfield(Bytes(4))
    type: ValueType = csfield(TEnum(Int32ul, ValueType))
    _val: Union[int, float] = csfield(IfThenElse(this.type == ValueType.FLOAT, RestreamData(this.val_bytes, Float32l), RestreamData(this.val_bytes, Int32sl)))

    value: Union[str, int, float] = csfield(Computed(convert_value))


@dataclass
class CBINData(DataclassMixin):
    _string_table: list[str] = csfield(Pointer(this._root.header.string_table_offset - DataclassStruct(CBINHeader).sizeof(), Array(this._root.header.string_table_count, CString("iso_8859_1"))))
    num_labels: int = csfield(Int32ul)
    labels: list[CBINLabel] = csfield(Array(this.num_labels, DataclassStruct(CBINLabel)))
    entries: list[CBINEntry] = csfield(Array(lambda this: sum(label.num_ents for label in this.labels) + sum(1 if label.num_ents > 0 else 0 for label in this.labels), DataclassStruct(CBINEntry)))
    values: list[CBINValue] = csfield(Array(lambda this: sum(ent.num_vals for ent in this.entries), DataclassStruct(CBINValue)))


@dataclass
class CBINFile(DataclassMixin):
    header: CBINHeader = csfield(DataclassStruct(CBINHeader))
    data: CBINData = csfield(XorCrypted(DataclassStruct(CBINData), this.header.xor_key))

    def to_dict(self) -> dict:
        out = OrderedDict()
        entries = self.data.entries
        values = self.data.values

        for label in self.data.labels:
            while len(entries) > 0 and entries[0].is_nil:
                entries = entries[1:]

            my_entries = entries[:label.num_ents]
            entries = entries[label.num_ents:]

            label_name = label.name.upper() if label.name else ''
            label_entries = []

            for entry in my_entries:
                entry_values = list(map(lambda v: v.value, values[:entry.num_vals]))
                values = values[entry.num_vals:]

                if len(entry_values) == 1:
                    entry_values = entry_values[0]
                elif len(entry_values) == 0:
                    entry_values = None
                else:
                    entry_values = tuple(entry_values)

                label_entries.append((entry.name, entry_values))

            if label_name in out:
                log.warning(f"duplicate label {entry.name}")
            out[label_name] = label_entries

        return out


def inspect_cmd(args):
    format = DataclassStruct(CBINFile)

    cbin = format.parse_stream(args.file)

    print(cbin)
    print("")

    print(f"Number of labels: {len(cbin.data.labels)}")
    print(f"label counts: {[label.num_ents for label in cbin.data.labels]}")
    print(f"Total entries for labels: {sum(label.num_ents for label in cbin.data.labels)}")
    print(f"Total number of values: {sum(ent.num_vals for ent in cbin.data.entries)}")

    return True


def dump_cmd(args):
    encoding = "utf8" if args.unicode else "iso_8859_1"
    format = DataclassStruct(CBINFile)

    cbin = format.parse_stream(args.file)

    args.out.write(b";; Generated from CBIN file by ttfrev\r\n")

    config_dict = cbin.to_dict()

    for label, entries in config_dict.items():
        if label != '':
            args.out.write(f"[{label}]\r\n".encode(encoding))

        for name, values in entries:
            if values is None:
                values = tuple()
            elif not isinstance(values, tuple):
                values = values,

            tab_align = (3 - len(name) // 8) * '\t'
            args.out.write(f"{name}{tab_align}= {','.join(map(str, values))}\r\n".encode(encoding))

        args.out.write(b"\r\n")

    return True


def group_runs(val: tuple[str, tuple[Union[int, float, str]]]) -> list[tuple[str, list[Union[int, float, str]]]]:
    runs = itertools.groupby(val, lambda ent: ent[0])
    return list(map(lambda group: (group[0], list(map(lambda item: item[1], group[1]))), runs))


def dump_json_cmd(args):
    format = DataclassStruct(CBINFile)

    cbin = format.parse_stream(args.file)

    data = cbin.to_dict()

    data = [{"label": label, "entries": list(map(lambda ent: {"entry": ent[0], "value": ent[1]}, entries))} for label, entries in data.items()]

    json.dump(data, args.out, indent=4)

    return True


if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    script_name = Path(sys.argv[0]).stem

    parser = argparse.ArgumentParser(description="CBIN file utility")
    cmd_parsers = parser.add_subparsers(required=True, metavar="cmd")

    inspect_parser = cmd_parsers.add_parser(
        "inspect", aliases=["i"], help="inspect a CBIN file"
    )
    inspect_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="CBIN file to operate on",
    )
    inspect_parser.set_defaults(handler=inspect_cmd)

    dump_parser = cmd_parsers.add_parser(
        "dump", aliases=["d"], help="dump CBIN in engine INI format"
    )
    dump_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="CBIN file to operate on",
    )
    dump_parser.add_argument(
        "-o",
        "--out",
        metavar="FILE",
        type=argparse.FileType("wb"),
        help="file to write dumped contents to (default: stdout)",
        default=sys.stdout.buffer,
    )
    dump_parser.add_argument(
        "-u",
        "--unicode",
        action="store_true",
        help="dump in non-engine-compatible UTF-8 encoding (default: ISO-8859-1)",
    )
    dump_parser.set_defaults(handler=dump_cmd)

    dump_json_parser = cmd_parsers.add_parser(
        "dump-json", aliases=["j"], help="dump CBIN in custom JSON format"
    )
    dump_json_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="CBIN file to operate on",
    )
    dump_json_parser.add_argument(
        "-o",
        "--out",
        dest="out",
        metavar="FILE",
        type=argparse.FileType("w"),
        help="file to write dumped contents to (default: stdout)",
        default=sys.stdout,
    )
    dump_json_parser.set_defaults(handler=dump_json_cmd)

    args = parser.parse_args()

    try:
        res = args.handler(args)
    except BrokenPipeError:
        log.error(f"{script_name}: Broken pipe")
        sys.exit(2)
    if not res:
        sys.exit(1)
