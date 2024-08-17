#!/usr/bin/env python3

from dataclasses import dataclass
from construct import (
    Lazy,
    LazyArray,
    Byte,
    Bitwise,
    Bytes,
    Rebuild,
    Const,
    Int32ul,
    If,
    IfThenElse,
    this,
    Hex,
    PaddedString,
    Pointer,
    OneOf,
    Flag,
    len_,
    Computed,
    Check,
    Timestamp,
    obj_,
    Padding,
)
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield
from typing import Any, Optional

from .common import XorCrypted, SPACE_EXE_KEY

import math
from datetime import datetime


@dataclass
class PFF3EntryFlags(DataclassMixin):
    # fields unk1-unk32
    _pad1: Any = csfield(Padding(23))
    encrypted: bool = csfield(Flag)
    _pad2: Any = csfield(Padding(8))


@dataclass
class PFF3Entry(DataclassMixin):
    flags: PFF3EntryFlags = csfield(Bitwise(DataclassStruct(PFF3EntryFlags)))
    # flags: int = csfield(Hex(Int32ul))
    offset: int = csfield(
        Hex(Int32ul),
    )
    length: int = csfield(Rebuild(Hex(Int32ul), lambda this: this.content.sizeof()))
    _mod_timestamp: int = csfield(
        Rebuild(Int32ul, lambda this: int(this.modified_at.timestamp()))
    )
    name: str = csfield(PaddedString(16, "ascii"))
    unk2: Optional[int] = csfield(If(this._.header.version == 0x24, Hex(Int32ul)))

    modified_at: datetime = csfield(
        Computed(lambda this: datetime.fromtimestamp(this._mod_timestamp))
    )
    content: bytes = csfield(Pointer(this.offset, Lazy(IfThenElse(this.flags.encrypted, XorCrypted(Bytes(this.length), SPACE_EXE_KEY), Bytes(this.length)))))

    def extract_entry_to_file(self, *, directory):
        with open(directory / self.name, "wb") as outf:
            outf.write(self.content())


@dataclass
class PFF3Header(DataclassMixin):
    length: int = csfield(
        Rebuild(Hex(Int32ul), lambda this: DataclassStruct(PFF3Header).sizeof())
    )
    signature: bytes = csfield(Const(b"PFF3"))
    num_entries: int = csfield(Rebuild(Int32ul, len_(this.entry_table.entries)))
    version: int = csfield(OneOf(Hex(Int32ul), [0x20, 0x24]))
    entry_table_offset: int = csfield(Hex(Int32ul))

    _assert_length: Any = csfield(
        Check(lambda this: DataclassStruct(PFF3Header).sizeof() == this.length)
    )


@dataclass
class PFF3File(DataclassMixin):
    header: PFF3Header = csfield(DataclassStruct(PFF3Header))
    entries: list[PFF3Entry] = csfield(
        Pointer(
            this.header.entry_table_offset,
            LazyArray(this.header.num_entries, DataclassStruct(PFF3Entry)),
        )
    )


def inspect_cmd(args):
    import binascii

    format = DataclassStruct(PFF3File)

    pff = format.parse_stream(args.file)

    print(pff)

    print(f"Listing {pff.header.num_entries} PFF entries.")
    for ent in pff.entries:
        input("Press <Enter> to continue.")
        print(ent)

    return True


def list_cmd(args):
    format = DataclassStruct(PFF3File)

    pff = format.parse_stream(args.file)

    for ent in pff.entries:
        print(ent.name)
    return True


def extract_cmd(args):
    from fnmatch import fnmatch
    from pathlib import Path

    format = DataclassStruct(PFF3File)

    pff = format.parse_stream(args.file)
    assert pff.header.length == 0x14, "PFF3 header is not of expected length!"

    # Ensure dest dir exists
    args.directory.mkdir(parents=True, exist_ok=True)

    found_entries = False
    lower_entry_names = tuple(map(lambda ent: ent.lower(), args.entry_names))
    for ent in pff.entries:
        iname = ent.name.lower()
        for name_pat in lower_entry_names:
            if fnmatch(iname, name_pat):
                extra = ""
                if ent.flags.encrypted:
                    extra = " (encrypted)"
                print(f"Extracting {ent.name}", extra)
                ent.extract_entry_to_file(directory=args.directory)
                found_entries = True
                break

    if not found_entries:
        print(f"Failed to find {args.entry_name} in PFF file!")
    return found_entries


if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description="PFF3 file utility")
    cmd_parsers = parser.add_subparsers(required=True, metavar="cmd")

    inspect_parser = cmd_parsers.add_parser(
        "inspect", aliases=["i"], help="inspect a PFF3 file interactively"
    )
    inspect_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="PFF3 file to operate on",
    )
    inspect_parser.set_defaults(handler=inspect_cmd)

    list_parser = cmd_parsers.add_parser(
        "list", aliases=["ls"], help="list all entries in a PFF file"
    )
    list_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="PFF3 file to operate on",
    )
    list_parser.set_defaults(handler=list_cmd)

    extract_parser = cmd_parsers.add_parser(
        "extract", aliases=["x"], help="extract file entry from a PFF file"
    )
    extract_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="PFF3 file to operate on",
    )
    extract_parser.add_argument(
        "-C",
        "--directory",
        dest="directory",
        type=Path,
        default=Path("."),
        help="directory to extract to",
    )

    extract_parser.add_argument(
        "entry_names",
        metavar="ENTRY",
        nargs="*",
        type=str,
        help="Entries to extract. Also accepts UNIX-style file path globs as processed by fnmatch. If unspecified, all are extracted.",
    )
    extract_parser.set_defaults(handler=extract_cmd, entry_names=["*"])

    args = parser.parse_args()
    res = args.handler(args)
    if not res:
        sys.exit(1)
