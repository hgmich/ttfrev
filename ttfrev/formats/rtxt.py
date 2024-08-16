#!/usr/bin/env python3
import logging

log = logging.Logger(__package__)

from dataclasses import dataclass
from construct import (
    Aligned,
    Bytes,
    Rebuild,
    Default,
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
    Debugger,
    CString,
    Float32l,
    RawCopy,
    IfThenElse,
    FixedSized,
    RestreamData,
    Tell,
    Lazy,
)
from construct.core import possiblestringencodings
from construct_dataclasses import DataclassStruct, csfield, subcsfield, to_struct
from typing import Any, Union, Optional

from collections import OrderedDict
import json
import itertools

from .common import XorCrypted, hex_or_dec_int


# Force construct to support ISO-8859-1 encoding for CString
possiblestringencodings["iso_8859_1"] = 1


@dataclass
class RTXTHeader:
    signature: bytes = csfield(Const(b"RTXT"))
    key_table_offset: int = csfield(Default(Hex(Int32ul), 0))
    key_table_length: int = csfield(Rebuild(Hex(Int32ul), 0))
    _string_count: int = csfield(Rebuild(Int32ul, lambda this: len(this._root.data.strings)))


@dataclass
class RTXTStringEntry:
    # This offset is relative to the end of RTXTHeader
    _str_offset: int = csfield(Hex(Int32ul))
    value: str = csfield(Pointer(lambda this: to_struct(RTXTHeader).sizeof() + (to_struct(RTXTHeader).sizeof() * (this._root.header._string_count or len(this._.strings))) + this._str_offset, CString("iso_8859_1")))
    unk_1: int = csfield(Const(0, Hex(Int32ul)))
    _section_id: int = csfield(Hex(Int32ul))
    section: str = csfield(Lazy(Computed(lambda this: this._.section_data._sect_names[this._section_id])))
    unk_3: int = csfield(Const(0, Hex(Int32ul)))


@dataclass
class RTXTSection:
    _offset: int = csfield(Int32ul)
    _num_strings: int = csfield(Int32ul)
    name: str = csfield(Computed(lambda this: this._._sect_names[this._index]))
    section_keys: list[str] = csfield(
        Pointer(
            lambda this: this._root.header.key_table_offset + this._offset + 4,
            Array(this._num_strings, CString("iso_8859_1")),
        )
    )


@dataclass
class RTXTSectionData:
    _num_sects: int = csfield(Rebuild(Int32ul, len_(this.sections)))
    _sect_names: list[str] = csfield(
        Rebuild(Pointer(
            lambda this: this._root.header.key_table_offset
            + (this._num_sects * DataclassStruct(RTXTSection).sizeof() + 4),
            Array(this._num_sects, CString("iso_8859_1")),
        ), lambda this: list(map(lambda sect: sect.name, this.sections)))
    )
    sections: list[RTXTSection] = subcsfield(RTXTSection,
        Array(this._num_sects, to_struct(RTXTSection))
    )


@dataclass
class RTXTData:
    strings: list[RTXTStringEntry] = subcsfield(RTXTStringEntry,
        Array(lambda this: this._root.header._string_count or len(this.strings), to_struct(RTXTStringEntry))
    )
    _string_table: list[str] = csfield(
        Aligned(4, Array(lambda this: this._root.header._string_count or len(this.strings) or 0, CString("iso_8859_1")))
    )
    section_data: RTXTSectionData = csfield(Rebuild(to_struct(RTXTSectionData), RTXTSectionData(sections=[])))



@dataclass
class RTXTFile:
    header: RTXTHeader = csfield(Rebuild(to_struct(RTXTHeader), RTXTHeader()))
    data: RTXTData = csfield(RTXTData)

    def to_dict(self) -> dict:
        out = OrderedDict()

        stridx = 0
        for section in self.data.section_data.sections:
            section_dict = OrderedDict()
            for k in section.section_keys:
                section_dict[k] = self.data._string_table[stridx]
                stridx += 1
            out[section.name] = section_dict

        return out


def inspect_cmd(args):
    format = DataclassStruct(RTXTFile)

    rtxt = format.parse_stream(args.file)

    print(rtxt)
    print("")

    print(f"Number of sections: {rtxt.data.section_data._num_sects}")
    print(
        f"Total string count: {sum(section._num_strings for section in rtxt.data.section_data.sections)}"
    )

    return True


def lookup_cmd(args):
    format = DataclassStruct(RTXTFile)

    rtxt = format.parse_stream(args.file)

    if args.index is not None:
        try:
            item = rtxt.data.strings[args.index]
        except IndexError:
            sys.stderr.write(f"entry index {args.index} not present in file\n")
            return False
        section = rtxt.data.section_data.sections[item._section_id]
        ents = sum(sect._num_strings for sect in rtxt.data.section_data.sections[:item._section_id])
        rel_key = args.index - ents
        key = section.section_keys[rel_key]
        section_name = section.name
        item_value = item.value
    elif args.label is not None or args.element is not None:
        if not args.label or not args.element:
            sys.stderr.write("must specify --label and --element\n")
            return False
        lookup = rtxt.to_dict()
        if (section := lookup.get(args.label)) is None:
            sys.stderr.write(f"section {args.label} not present in file\n")
            return False
        section_name = args.label
        item_value = section.get(args.element)
        if item_value is None:
            sys.stderr.write(f"element {args.element} not present in section {args.label}\n")
            return False
        key = args.element
        
    else:
        sys.stderr.write("must specify either --index or --label + --element\n")
        return False

    print(f"Value: '{item_value}'")
    print(f"Section: {section_name}")
    print(f"Key: {key}")
    print(f"{section_name}.{key} ('{item_value}')")

    return True


def build_cmd(args):
    format = DataclassStruct(RTXTFile)

    struct = RTXTFile(
        data=RTXTData(strings=[RTXTStringEntry(_str_offset=0, value="foo", _section_id=0)], _string_table=["foo"]),
    )

    # format.build_stream(struct, args.file)
    print(struct)
    print(struct.data.section_data)
    print("")
    built = format.build(struct)
    unbuilt = format.parse(built)
    print(unbuilt)
    print("fixup")
    rebuilt = format.build(unbuilt)
    reunbuilt = format.parse(built)
    print(reunbuilt)
    rebuilt = format.build(reunbuilt)
    reunbuilt = format.parse(built)
    print(reunbuilt)

    return True


def dump_cmd(args):
    encoding = "utf8" if args.unicode else "iso_8859_1"
    format = DataclassStruct(RTXTFile)

    rtxt = format.parse_stream(args.file)

    args.out.write(b";; Generated from RTXT file by ttfrev\r\n")

    txt_dict = rtxt.to_dict()

    for section, strings in txt_dict.items():
        if section != "":
            args.out.write(f"[{section}]\r\n".encode(encoding))

        for key, s in strings.items():
            lines = s.replace("\r\n", "\n").split("\n")
            if len(lines) > 1:
                args.out.write(b"\r\n")
            for line in lines:
                tab_align = max((3 - len(key) // 8), 1) * "\t"
                args.out.write(f"{key}{tab_align}= {line}\r\n".encode(encoding))
            if len(lines) > 1:
                args.out.write(b"\r\n")
            
        args.out.write(b"\r\n")

    return True


def group_runs(
    val: tuple[str, tuple[Union[int, float, str]]]
) -> list[tuple[str, list[Union[int, float, str]]]]:
    runs = itertools.groupby(val, lambda ent: ent[0])
    return list(
        map(lambda group: (group[0], list(map(lambda item: item[1], group[1]))), runs)
    )


def dump_json_cmd(args):
    format = DataclassStruct(CBINFile)

    cbin = format.parse_stream(args.file)

    data = cbin.to_dict()

    data = [
        {
            "label": label,
            "entries": list(
                map(lambda ent: {"entry": ent[0], "value": ent[1]}, entries)
            ),
        }
        for label, entries in data.items()
    ]

    json.dump(data, args.out, indent=4)

    return True


if __name__ == "__main__":
    import argparse
    import sys
    from pathlib import Path

    script_name = Path(sys.argv[0]).stem

    parser = argparse.ArgumentParser(description="RTXT file utility")
    cmd_parsers = parser.add_subparsers(required=True, metavar="cmd")

    inspect_parser = cmd_parsers.add_parser(
        "inspect", aliases=["i"], help="inspect a RTXT file"
    )
    inspect_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="RTXT file to operate on",
    )
    inspect_parser.set_defaults(handler=inspect_cmd)

    lookup_parser = cmd_parsers.add_parser(
        "lookup", aliases=["l"], help="lookup a string in an RTXT file"
    )
    lookup_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="RTXT file to operate on",
    )
    lookup_parser.add_argument(
        "-i",
        "--index",
        metavar="INDEX",
        type=hex_or_dec_int,
        help="index of string to lookup (either hex or decimal)",
        default=None,
    )
    lookup_parser.add_argument(
        "-l",
        "--label",
        metavar="STRING",
        type=str,
        help="index of string to lookup",
        default=None,
    )
    lookup_parser.add_argument(
        "-e",
        "--element",
        metavar="STRING",
        type=str,
        help="element of string to lookup",
        default=None,
    )
    lookup_parser.set_defaults(handler=lookup_cmd)

    build_parser = cmd_parsers.add_parser(
        "build", aliases=["b"], help="build a RTXT file"
    )
    build_parser.add_argument(
        "file",
        metavar="[FILE]",
        type=argparse.FileType("wb"),
        help="file to write dumped contents to (default: stdout)",
        default=sys.stdout.buffer,
    )
    build_parser.set_defaults(handler=build_cmd)

    dump_parser = cmd_parsers.add_parser(
        "dump", aliases=["d"], help="dump RTXT in engine INI format"
    )
    dump_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="RTXT file to operate on",
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
        "dump-json", aliases=["j"], help="dump RTXT in custom JSON format"
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
