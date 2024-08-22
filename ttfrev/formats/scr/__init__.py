#!/usr/bin/env python3

from dataclasses import dataclass
from construct import (
    HexDisplayedInteger,
    Lazy,
    Array,
    LazyArray,
    Byte,
    Bytes,
    Rebuild,
    Const,
    Int8ul,
    Prefixed,
    CString,
    Int32ul,
    this,
    Hex,
    PaddedString,
    Padding,
    Pointer,
    len_,
    Computed,
    Check,
    Timestamp,
    obj_,
    Tell,
)
from construct.lib.hex import HexDisplayedBytes
from construct_typed import DataclassMixin, DataclassStruct, EnumBase, TEnum, csfield
from typing import Any
from pathlib import Path

from ttfrev.formats.common import LOG_FORMAT
from .bytecode import Interpreter, SoundCmd, SwitchScript, parse_bytecode, BytecodeOp

import math
from datetime import datetime

import logging


logger = logging.getLogger(__name__)


@dataclass
class SCREntry(DataclassMixin):
    _file_start: int = csfield(Tell)
    signature: bytes = csfield(Const(b"MU01"))
    field_4: int = csfield(Hex(Int32ul))
    name: str = csfield(PaddedString(16, "ascii"))
    block0_size: int = csfield(Hex(Int32ul))
    block1_size: int = csfield(Hex(Int32ul))
    script_base_offset: int = csfield(Hex(Int32ul))
    _code_labels_offset: int = csfield(Hex(Int32ul))
    _code_labels_count: int = csfield(Hex(Int32ul))
    next_code_label: int = csfield(Hex(Int32ul))
    array2_ptr: int = csfield(Hex(Int32ul))
    array2_count: int = csfield(Hex(Int32ul))
    _file_name_offset: int = csfield(Hex(Int32ul))
    _file_name_len: int = csfield(Hex(Int32ul))
    field_40: int = csfield(Hex(Int32ul))
    field_44: int = csfield(Hex(Int32ul))
    file_name: str = csfield(Pointer(this._file_start + this._file_name_offset, PaddedString(this._file_name_len, "ascii")))
    code_labels: list[HexDisplayedInteger] = csfield(Pointer(this._file_start + this._code_labels_offset, Array(this._code_labels_count, Hex(Int32ul))))
    script_bytes: bytes = csfield(Pointer(this._file_start + this.script_base_offset, Bytes(this.array2_ptr - this.script_base_offset)))
    script: list[BytecodeOp] = csfield(Computed(lambda this: parse_bytecode(this.script_bytes)))


@dataclass
class SCRHeader(DataclassMixin):
    signature: bytes = csfield(Const(b"SCR0"))
    unk0: int = csfield(Const(0x100, Hex(Int32ul)))
    num_script_entries: int = csfield(Rebuild(Int32ul, len_(this._.entries)))
    script_entries_offset: int = csfield(Hex(Int32ul))
    num_cmds: int = csfield(Hex(Int32ul))
    cmd_name_table_offset: int = csfield(Hex(Int32ul))
    cmd_table_offset: int = csfield(Hex(Int32ul))
    _pad: Any = csfield(Padding(16))

    # _assert_length: Any = csfield(
    #     Check(lambda this: DataclassStruct(PFF3Header).sizeof() == this.length)
    # )


@dataclass
class SCREntPtr(DataclassMixin):
    _val: int = csfield(Hex(Int32ul))
    entry: SCREntry = csfield(Pointer(this._val, DataclassStruct(SCREntry)))


@dataclass
class SCRFile(DataclassMixin):
    header: SCRHeader = csfield(DataclassStruct(SCRHeader))
    entry_table: list[SCREntPtr] = csfield(Array(this.header.num_script_entries, DataclassStruct(SCREntPtr)))
    commands: list[str] = csfield(Pointer(this.header.cmd_name_table_offset, Array(this.header.num_cmds, Prefixed(Int8ul, CString("ascii"), includelength=True))))
    # entries: list[SCREntry] = csfield(
    #     LazyArray(this.header.num_entries, DataclassStruct(SCREntry)),
    # )


def inspect_cmd(args):
    import binascii

    format = DataclassStruct(SCRFile)

    scr = format.parse_stream(args.file)

    if scr is None:
        raise TypeError("Invalid SCR file")

    print(scr.header)
    print(scr.commands)

    print(f"Listing {len(scr.entry_table)} SCR entries.")
    for ent in scr.entry_table:
        input("Press <Enter> to continue.")
        print(ent)

    return True


def list_cmd(args):
    format = DataclassStruct(SCRFile)

    scr = format.parse_stream(args.file)

    if scr is None:
        raise TypeError("Invalid SCR file")

    for ent in scr.entry_table:
        print(ent.entry.name)
    return True


def disassemble_cmd(args):
    format = DataclassStruct(SCRFile)

    scr = format.parse_stream(args.file)

    if scr is None:
        raise TypeError("Invalid SCR file")

    script_entry: SCREntry = scr.entry_table[args.script_idx].entry
    script_labels = {(v - script_entry.script_base_offset):i for i, v in enumerate(script_entry.code_labels)}

    pc = 0
    for op in script_entry.script:
        if (label_idx := script_labels.get(pc)) is not None:
            print(f"\n$org .Script_{label_idx:02X}")
        if isinstance(op, SoundCmd):
            cmd = scr.commands[op.command_id]
            op_str = f"{op.mnemonic} {cmd}"
        elif isinstance(op, SwitchScript):
            op_str = f"{op.mnemonic} .Script_{op.entry_point:02X}"
        else:
            op_str = str(op)
        print(f"{pc:X}: {op_str}")
        pc += (op.operands_len + 1)


def execute_cmd(args):
    format = DataclassStruct(SCRFile)

    scr = format.parse_stream(args.file)

    if scr is None:
        raise TypeError("Invalid SCR file")

    script_entry: SCREntry = scr.entry_table[args.script_idx].entry
    vm = Interpreter(
        block0_size=script_entry.block0_size,
        block1_size=script_entry.block1_size,
        ip=script_entry.next_code_label,
        entry_points=[(addr - script_entry.script_base_offset) for addr in script_entry.code_labels],
        script=script_entry.script_bytes,
        cmd_list=scr.commands,
    )

    vm.run(step=args.step)


def main():
    import argparse
    import sys
    from pathlib import Path

    parser = argparse.ArgumentParser(description="SCR file inspector")

    parser.add_argument(
        "-v",
        dest="log_level",
        action="count",
        default=0,
        help="enable additional logging (-v: info, -vv: debug)"
    )

    cmd_parsers = parser.add_subparsers(required=True, metavar="cmd")

    inspect_parser = cmd_parsers.add_parser(
        "inspect", aliases=["i"], help="inspect a SCR file interactively"
    )
    inspect_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="SCR file to operate on",
    )
    inspect_parser.set_defaults(handler=inspect_cmd)

    list_parser = cmd_parsers.add_parser(
        "list", aliases=["ls"], help="list all entries in an SCR file"
    )
    list_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="SCR file to operate on",
    )
    list_parser.set_defaults(handler=list_cmd)

    disassemble_parser = cmd_parsers.add_parser(
        "disassemble", aliases=["d", "dis"], help="disassemble script"
    )
    disassemble_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="SCR file to operate on",
    )
    disassemble_parser.add_argument(
        "script_idx",
        metavar="SCRIPT",
        type=int,
        help="Which script to list disassembly for",
    )
    disassemble_parser.set_defaults(handler=disassemble_cmd)

    execute_parser = cmd_parsers.add_parser(
        "execute", aliases=["e", "exec"], help="execute script"
    )
    execute_parser.add_argument(
        "file",
        metavar="FILE",
        type=argparse.FileType("rb"),
        help="SCR file to operate on",
    )
    execute_parser.add_argument(
        "script_idx",
        metavar="SCRIPT",
        type=int,
        help="Which script to list disassembly for",
    )
    execute_parser.add_argument(
        "-e",
        "--entry-point",
        dest="entry_point",
        type=int,
        default=0,
        help="which entry point to use",
    )

    execute_parser.add_argument(
        "-s",
        "--step-through",
        dest="step",
        action="store_true",
        default=False,
        help="step through execution op-by-op",
    )
    execute_parser.set_defaults(handler=execute_cmd)

    args = parser.parse_args()

    match args.log_level:
        case 1:
            log_level = logging.INFO
        case lvl if lvl >= 2:
            log_level = logging.DEBUG
        case _:
            log_level = logging.WARNING

    logging.basicConfig(format=LOG_FORMAT, level=log_level)

    if args.log_level > 2:
        logger.warning("verbosity levels above 2 have no effect")

    res = args.handler(args)
    if not res:
        sys.exit()
