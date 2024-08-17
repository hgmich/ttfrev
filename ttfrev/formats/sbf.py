#!/usr/bin/env python3
#
from dataclasses import dataclass
from typing_extensions import Optional
from construct import (
    Lazy,
    LazyArray,
    Byte,
    Bytes,
    Rebuild,
    Const,
    Int32ul,
    this,
    Hex,
    PaddedString,
    Pointer,
    len_,
    Computed,
    Check,
    Timestamp,
    obj_,
)
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield
from typing import Any
from pathlib import Path

import math
from datetime import datetime


@dataclass
class SBFEntry(DataclassMixin):
    name: str = csfield(PaddedString(16, "ascii"))
    offset: int = csfield(Hex(Int32ul))
    length: int = csfield(Rebuild(Hex(Int32ul), lambda this: this.content.sizeof()))
    unk2: int = csfield(Hex(Int32ul))
    unk3: int = csfield(Hex(Int32ul))
    content: bytes = csfield(Pointer(this.offset, Lazy(Bytes(this.length))))

    def extract_entry_to_file(self, *, directory: Path, name: Optional[str] = None):
        with open((directory / (name or self.name)).with_suffix(".sbe"), "wb") as outf:
            outf.write(self.content())


@dataclass
class SBFHeader(DataclassMixin):
    signature: bytes = csfield(Const(b"SBF0"))
    unk0: int = csfield(Const(0x100, Hex(Int32ul)))
    unk1: int = csfield(Const(0x11, Hex(Int32ul)))
    unk2: int = csfield(Const(0x0, Hex(Int32ul)))
    unk3: int = csfield(Const(0x18, Hex(Int32ul)))
    num_entries: int = csfield(Rebuild(Int32ul, len_(this._.entries)))
    # length: int = csfield(
    #     Rebuild(Hex(Int32ul), lambda this: DataclassStruct(PFF3Header).sizeof())
    # )
    # num_entries: int = csfield(Rebuild(Int32ul, len_(this.entry_table.entries)))
    # version: int = csfield(Const(0x24, Hex(Int32ul)))
    # entry_table_offset: int = csfield(Hex(Int32ul))

    # _assert_length: Any = csfield(
    #     Check(lambda this: DataclassStruct(PFF3Header).sizeof() == this.length)
    # )


@dataclass
class SBFFile(DataclassMixin):
    header: SBFHeader = csfield(DataclassStruct(SBFHeader))
    entries: list[SBFEntry] = csfield(
        LazyArray(this.header.num_entries, DataclassStruct(SBFEntry)),
    )


def inspect_cmd(args):
    import binascii

    format = DataclassStruct(SBFFile)

    sbf = format.parse_stream(args.file)

    print(sbf)

    print(f"Listing {sbf.header.num_entries} SBF entries.")
    for ent in sbf.entries:
        input("Press <Enter> to continue.")
        print(ent)

    return True


def list_cmd(args):
    format = DataclassStruct(SBFFile)

    sbf = format.parse_stream(args.file)

    for ent in sbf.entries:
        print(ent.name)
    return True


def extract_cmd(args):
    from fnmatch import fnmatch
    from pathlib import Path

    format = DataclassStruct(SBFFile)

    sbf = format.parse_stream(args.file)

    # Ensure dest dir exists
    args.directory.mkdir(parents=True, exist_ok=True)

    found_entries = False
    lower_entry_names = tuple(map(lambda ent: ent.lower(), args.entry_names))
    i = 0
    for ent in sbf.entries:
        # name = ent.name
        name = f"snd_{i:X}"
        iname = name.lower()
        for name_pat in lower_entry_names:
            if fnmatch(iname, name_pat):
                print(f"Extracting {name}")
                ent.extract_entry_to_file(directory=args.directory, name=name)
                found_entries = True
                break
        i += 1

    if not found_entries:
        print(f"Failed to find {args.entry_name} in PFF file!")
    return found_entries


if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description="SBF file inspector")
    cmd_parsers = parser.add_subparsers(required=True, metavar="cmd")

    inspect_parser = cmd_parsers.add_parser(
        "inspect", aliases=["i"], help="inspect a SBF file interactively"
    )
    inspect_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="SBF file to operate on",
    )
    inspect_parser.set_defaults(handler=inspect_cmd)

    list_parser = cmd_parsers.add_parser(
        "list", aliases=["ls"], help="list all entries in an SBF file"
    )
    list_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="PFF3 file to operate on",
    )
    list_parser.set_defaults(handler=list_cmd)

    extract_parser = cmd_parsers.add_parser(
        "extract", aliases=["x"], help="extract file entry from an SBF file"
    )
    extract_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="SBF file to operate on",
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
        sys.exit()
