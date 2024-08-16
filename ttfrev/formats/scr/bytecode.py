from os import W_OK
import struct
from typing import Optional, ClassVar, Any, Callable, Generic, TypeVar
from collections import defaultdict
from io import BufferedIOBase, BytesIO


T = TypeVar("T")
R = TypeVar("R")


class classproperty(Generic[T, R]):
    def __init__(self, func: Callable[[type[T]], R]) -> None:
        self.func = func

    def __get__(self, obj: Any, cls: type[T]) -> R:
        return self.func(cls)


class BytecodeOp:
    _operand_bytes: bytes

    opcode: int
    mnemonic: str
    operand_format: ClassVar[Optional[str]] = None

    @classproperty
    def is_valid(cls) -> bool:
        return True

    @classproperty
    def operands_len(cls) -> int:
        """
        Length of operands consumed, in bytes.
        """
        if cls.operand_format is None:
            return 0

        return struct.calcsize(cls.operand_format)

    @property
    def operands(self) -> tuple[int, ...]:
        if self.operand_format is None:
            return tuple()
        return struct.unpack(self.operand_format, self._operand_bytes)

    def __str__(self) -> str:
        if len(self.operands) == 0:
            return self.mnemonic
        operands = ', '.join(map(lambda oper: f"{oper:X}h", self.operands))
        return f"{self.mnemonic} {operands}"

    def __repr__(self) -> str:
        return f"<scr op {self.opcode:02X}: '{str(self)}'>"

    def __init__(self, operands: bytes):
        assert len(operands) == self.operands_len
        self._operand_bytes = operands


class InvalidOp(BytecodeOp):
    def __init__(self, opcode: int):
        super().__init__(b"")
        self._opcode = opcode

    @property
    def opcode(self) -> int:
        return self._opcode

    @property
    def mnemonic(self) -> str:
        return f"<invalid op {self.opcode:2X}>"


class Nop(BytecodeOp):
    """
    Does nothing except clear the interpreter carry flag.
    """

    opcode = 0x00
    mnemonic = "NOP"


class PushByteImmediate(BytecodeOp):
    """
    Loads the lowest byte of the value stored at `i8` and pushes it to the top of the stack.
    """

    opcode = 0x01
    operand_format = "B"
    mnemonic = "PUSHB.I"

    @property
    def immediate(self) -> int:
        return self.operands[0]


class PushWordImmediate(BytecodeOp):
    """
    Loads the entire 32 bit value stored at `i8` and pushes it to the top of the stack.
    """

    opcode = 0x02
    operand_format = "<I"
    mnemonic = "PUSHW.I"

    @property
    def immediate(self) -> int:
        return self.operands[0]


class PushWordBlk0(BytecodeOp):
    """
    Loads the entire 32-bit value at index `i8` in data block 0 and pushes it to the top of the stack.
    """

    opcode = 0x03
    operand_format = "B"
    mnemonic = "PUSHW.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushWordBlk1(BytecodeOp):
    """
    Loads the entire 32-bit value at index `i8` in data block 0 and pushes it to the top of the stack.
    """

    opcode = 0x04
    operand_format = "B"
    mnemonic = "PUSHW.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushRefBlk0(BytecodeOp):
    """
    Loads the entire 32-bit value at index `i8` in data block 0 and pushes it to the top of the stack.
    """

    opcode = 0x05
    operand_format = "B"
    mnemonic = "PUSHP.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushRefBlk1(BytecodeOp):
    """
    Loads the entire 32-bit value at index `i8` in data block 1 and pushes it to the top of the stack.
    """

    opcode = 0x06
    operand_format = "B"
    mnemonic = "PUSHP.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushWordArray2(BytecodeOp):

    opcode = 0x06
    operand_format = "B"
    mnemonic = "PUSHW.A2"

    @property
    def index(self) -> int:
        return self.operands[0]


class PopWordBlk0(BytecodeOp):
    """
    """

    opcode = 0x08
    operand_format = "B"
    mnemonic = "POPW.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PopWordBlk1(BytecodeOp):
    """
    """

    opcode = 0x09
    operand_format = "B"
    mnemonic = "POPW.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PopMultipleWordsBlk0(BytecodeOp):
    """
    """

    opcode = 0x0A
    operand_format = "BB"
    mnemonic = "POPMW.BLK0"

    @property
    def start_slot(self) -> int:
        return self.operands[0]

    @property
    def size_bytes(self) -> int:
        return self.operands[1]


class PopMultipleWordsBlk1(BytecodeOp):
    """
    """

    opcode = 0x0B
    operand_format = "BB"
    mnemonic = "POPMW.BLK1"

    @property
    def start_slot(self) -> int:
        return self.operands[0]

    @property
    def size_bytes(self) -> int:
        return self.operands[1]


class PushControlBlock(BytecodeOp):
    """
    """

    opcode = 0x0C
    mnemonic = "PUSHCB"


class PopAll(BytecodeOp):
    """
    """

    opcode = 0x0F
    mnemonic = "POPALL"


class Add(BytecodeOp):
    """
    """

    opcode = 0x10
    mnemonic = "ADD"


class Subtract(BytecodeOp):
    """
    """

    opcode = 0x11
    mnemonic = "SUB"


class Multiply(BytecodeOp):
    """
    """

    opcode = 0x12
    mnemonic = "MUL"


class Divide(BytecodeOp):
    """
    """

    opcode = 0x13
    mnemonic = "DIV"


class Modulus(BytecodeOp):
    """
    """

    opcode = 0x14
    mnemonic = "MOD"


class LogicalAnd(BytecodeOp):
    """
    """

    opcode = 0x15
    mnemonic = "AND.L"


class LogicalOr(BytecodeOp):
    """
    """

    opcode = 0x16
    mnemonic = "OR.L"


class BitwiseAnd(BytecodeOp):
    """
    """

    opcode = 0x17
    mnemonic = "AND"


class BitwiseOr(BytecodeOp):
    """
    """

    opcode = 0x18
    mnemonic = "OR"


class BitwiseXor(BytecodeOp):
    """
    """

    opcode = 0x19
    mnemonic = "XOR"


class Negate(BytecodeOp):
    """
    """

    opcode = 0x1A
    mnemonic = "NEG"


class BitwiseNot(BytecodeOp):
    """
    """

    opcode = 0x1B
    mnemonic = "NOT"


class ShiftLeft(BytecodeOp):
    """
    """

    opcode = 0x1C
    mnemonic = "SHL"


class ArithmeticShiftRight(BytecodeOp):
    """
    """

    opcode = 0x1D
    mnemonic = "SHR"


class CompareZero(BytecodeOp):
    """
    """

    opcode = 0x1E
    mnemonic = "CMP.Z"


class Compare(BytecodeOp):
    """
    """

    opcode = 0x20
    mnemonic = "CMP"


class CompareNotEqual(BytecodeOp):
    """
    """

    opcode = 0x21
    mnemonic = "CMP.NE"


class CompareGreaterEqual(BytecodeOp):
    """
    """

    opcode = 0x22
    mnemonic = "CMP.GE"


class CompareLessEqual(BytecodeOp):
    """
    """

    opcode = 0x23
    mnemonic = "CMP.LE"


class CompareGreaterThan(BytecodeOp):
    """
    """

    opcode = 0x24
    mnemonic = "CMP.GT"


class CompareLessThan(BytecodeOp):
    """
    """

    opcode = 0x25
    mnemonic = "CMP.LT"


class IncrementBlk0(BytecodeOp):
    """
    """

    opcode = 0x28
    operand_format = "B"
    mnemonic = "INC.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class DecrementBlk0(BytecodeOp):
    """
    """

    opcode = 0x29
    operand_format = "B"
    mnemonic = "DEC.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class IncrementBlk1(BytecodeOp):
    """
    """

    opcode = 0x2A
    operand_format = "B"
    mnemonic = "INC.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class DecrementBlk1(BytecodeOp):
    """
    """

    opcode = 0x2B
    operand_format = "B"
    mnemonic = "DEC.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class JumpUnconditional(BytecodeOp):
    """
    """

    opcode = 0x30
    operand_format = "<I"
    mnemonic = "JMP"

    @property
    def target(self) -> int:
        return self.operands[0]


class JumpEqual(BytecodeOp):
    """
    """

    opcode = 0x31
    operand_format = "<I"
    mnemonic = "JEQ"

    @property
    def target(self) -> int:
        return self.operands[0]


class JumpNotEqual(BytecodeOp):
    """
    """

    opcode = 0x32
    operand_format = "<I"
    mnemonic = "JNE"

    @property
    def target(self) -> int:
        return self.operands[0]


class Unknown3(BytecodeOp):
    """
    """

    opcode = 0x33
    operand_format = "B"
    mnemonic = "UNK.3"

    @property
    def op0(self) -> int:
        return self.operands[0]


class Unknown4(BytecodeOp):
    """
    """

    opcode = 0x34
    operand_format = "<I"
    mnemonic = "UNK.4"

    @property
    def op0(self) -> int:
        return self.operands[0]


class Unknown5(BytecodeOp):
    """
    """

    opcode = 0x35
    operand_format = "B"
    mnemonic = "UNK.5"

    @property
    def op0(self) -> int:
        return self.operands[0]


class Pop(BytecodeOp):
    """
    """

    opcode = 0x38
    operand_format = "B"
    mnemonic = "POP"

    @property
    def num_slots(self) -> int:
        return self.operands[0]


class Test(BytecodeOp):
    """
    """

    opcode = 0x39
    mnemonic = "TEST"


class SwitchScript(BytecodeOp):
    """
    """

    opcode = 0x3B
    operand_format = "B"
    mnemonic = "SCR"

    @property
    def entry_point(self) -> int:
        return self.operands[0]


class PlaySoundHalfWord(BytecodeOp):
    """
    """

    opcode = 0x3D
    operand_format = "<H"
    mnemonic = "PLAY.H"

    @property
    def sound_id(self) -> int:
        return self.operands[0]


class PlaySoundByte(BytecodeOp):
    """
    """

    opcode = 0x3E
    operand_format = "B"
    mnemonic = "PLAY.B"

    @property
    def sound_id(self) -> int:
        return self.operands[0]


class RestartScript(BytecodeOp):
    """
    """

    opcode = 0x3F
    mnemonic = "SCR.RES"


class SoundCmd(BytecodeOp):
    """
    """

    opcode = 0x40
    operand_format = "B"
    mnemonic = "CMD"

    @property
    def command_id(self) -> int:
        return self.operands[0]


OPCODES: tuple[type[BytecodeOp], ...] = (
    Nop,
    PushByteImmediate,
    PushWordImmediate,
    PushWordBlk0,
    PushWordBlk1,
    PushRefBlk0,
    PushRefBlk1,
    PushWordArray2,
    PopWordBlk0,
    PopWordBlk1,
    PopMultipleWordsBlk0,
    PopMultipleWordsBlk1,
    PushControlBlock,
    PopAll,
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulus,
    LogicalAnd,
    LogicalOr,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    Negate,
    BitwiseNot,
    ShiftLeft,
    ArithmeticShiftRight,
    CompareZero,
    Compare,
    CompareNotEqual,
    CompareGreaterEqual,
    CompareLessEqual,
    CompareGreaterThan,
    CompareLessThan,
    IncrementBlk0,
    DecrementBlk0,
    IncrementBlk1,
    DecrementBlk1,
    JumpUnconditional,
    JumpEqual,
    JumpNotEqual,
    Unknown3,
    Unknown4,
    Unknown5,
    Pop,
    Test,
    SwitchScript,
    PlaySoundHalfWord,
    PlaySoundByte,
    RestartScript,
    SoundCmd,
)


OPCODE_LOOKUP: dict[int, type[BytecodeOp]] = {op.opcode:op for op in OPCODES}


def parse_bytecode(bytes: bytes | bytearray | memoryview | BufferedIOBase) -> list[BytecodeOp]:
    if isinstance(bytes, BufferedIOBase):
        bio = bytes
    else:
        bio = BytesIO(bytes)

    ops = []

    while True:
        opcode = bio.read(1)
        if len(opcode) < 1:
            break
        opcode = opcode[0]
        op_cls = OPCODE_LOOKUP.get(opcode)
        if op_cls is None:
            op = InvalidOp(opcode)
        else:
            operands = bio.read(op_cls.operands_len or 0)
            if len(operands) == 0 and op_cls.operands_len != 0:
                raise Exception(f"failed to read operand(s) for op {op_cls.mnemonic}: reached EOF")
            op = op_cls(operands)
        ops.append(op)

    return ops
