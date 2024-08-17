from os import W_OK
import struct
from typing import Optional, ClassVar, Any, Callable, Generic, TypeVar
from collections import defaultdict
from io import BufferedIOBase, BytesIO
import logging

from ttfrev.formats.common import have_debug


logger = logging.getLogger(__name__)


T = TypeVar("T")
R = TypeVar("R")


class classproperty(Generic[T, R]):
    def __init__(self, func: Callable[[type[T]], R]) -> None:
        self.func = func

    def __get__(self, obj: Any, cls: type[T]) -> R:
        return self.func(cls)


class BytecodeOp:
    """
    Opcode for the SCR bytecode interpreter.

    The vital info for the interpreter:
        * 32-bit stack-based virtual machine.
        * Ops are variable-length encoded, consisting of a single 8 bit opcode,
          and zero or more operand bytes, which may be interpreted as bytes,
          words (32-bit) or half-words (16-bit).
        * The stack "grows down"; space is allocated in the stack by adding to
          the stack pointer, and removed by subtracting from the stack pointer.
        * Ops may take stack parameters in addition to their operands. The ops
          use left-to-right push order based on division/subtraction
          conventions, such that for a 2-parameter op, the second parameter is
          at the top of the stack.
        * The interpreter has an unknown array (referred to as "array 2" for
          lack of better conventions) which is read only (results can only be
          read from).
        * The interpreter has two read-write global data blocks, inventively
          termed data block 0 and data block 1, with a script-configurable size
          (though the bytecode ops can only address 256 bytes per block).
        * Ops in the engine implementation pass the current stack pointer in
          x86 register %ebp and the current program counter in register %esi.
          The program counter register is used both to fetch operands, and for
          control flow ops to modify the script program counter.
        * Each script has a table of entry points which give several script
          locations execution can start from or be transferred to.
        * Each SCR file can contain multiple named scripts.
        * Each SCR file ends with a list of named script commands for
          operations such as sample playback volume adjustment, which the
          script bytecode indexes into for relevant ops.
    """
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
    __match_args__ = ('opcode',)
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
    Takes a single-byte `immediate`, word-extends it, and pushes it to the
    top of the stack.
    """

    __match_args__ = ('immediate',)

    opcode = 0x01
    operand_format = "B"
    mnemonic = "PUSHB.I"

    @property
    def immediate(self) -> int:
        return self.operands[0]


class PushWordImmediate(BytecodeOp):
    """
    Pushes the word-length `immediate` to the top of the stack.
    """

    __match_args__ = ('immediate',)

    opcode = 0x02
    operand_format = "<I"
    mnemonic = "PUSHW.I"

    @property
    def immediate(self) -> int:
        return self.operands[0]


class PushWordBlk0(BytecodeOp):
    """
    Loads a 32-bit value at index `slot` in data block 0 and pushes it
    to the top of the stack.
    """

    __match_args__ = ('slot',)

    opcode = 0x03
    operand_format = "B"
    mnemonic = "PUSHW.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushWordBlk1(BytecodeOp):
    """
    Loads a 32-bit value at index `slot` in data block 0 and pushes it
    to the top of the stack.
    """

    __match_args__ = ('slot',)

    opcode = 0x04
    operand_format = "B"
    mnemonic = "PUSHW.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushRefBlk0(BytecodeOp):
    """
    Pushes the machine pointer of index `slot` in data block 0 to the top of
    the stack.

    Note: In the engine, this is not a code pointer in the script! It's a
    pointer within the real address space of the interpreter.
    """

    __match_args__ = ('slot',)

    opcode = 0x05
    operand_format = "B"
    mnemonic = "PUSHP.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushRefBlk1(BytecodeOp):
    """
    Pushes the machine pointer of index `slot` in data block 1 to the top of
    the stack.

    NOTE: In the engine, this is not a code pointer in the script! It's a
    pointer within the real address space of the interpreter.
    """

    __match_args__ = ('slot',)

    opcode = 0x06
    operand_format = "B"
    mnemonic = "PUSHP.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PushWordArray2(BytecodeOp):
    """
    Loads the 32-bit value at index `slot` in "array 2" and pushes it to the
    top of the stack.
    """

    __match_args__ = ('slot',)


    opcode = 0x06
    operand_format = "B"
    mnemonic = "PUSHW.A2"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PopWordBlk0(BytecodeOp):
    """
    Remove the item at the top of the stack and store it into data block 0 at
    index `slot`.
    """

    __match_args__ = ('slot',)

    opcode = 0x08
    operand_format = "B"
    mnemonic = "POPW.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PopWordBlk1(BytecodeOp):
    """
    Remove the item at the top of the stack and store it into data block 1 at
    index `slot`.
    """

    __match_args__ = ('slot',)

    opcode = 0x09
    operand_format = "B"
    mnemonic = "POPW.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class PopMultipleWordsBlk0(BytecodeOp):
    """
    Remove `size_bytes` from the stack and store them in data block 0
    starting from index `slot`.

    IMPORTANT: Though the `size_bytes` operand is in bytes, not in words, the
    engine's interpreter will probably malfunction if `size_bytes` is not a
    multiple of 4.

    TODO: This also sets some internal flag in the interpreter?
    """

    __match_args__ = ('start_slot', 'size_bytes')

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
    Remove `size_bytes` from the stack and store them in data block 1
    starting from index `slot`.

    IMPORTANT: Though the `size_bytes` operand is in bytes, not in words, the
    engine's interpreter will probably malfunction if `size_bytes` is not a
    multiple of 4.

    NOTE: unlike POPMW.BLK0, this doesn't set an interpreter flag.
    """

    __match_args__ = ('start_slot', 'size_bytes')

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
    Pushes the machine pointer to the "script control block" (interpreter
    state) to the stack.

    NOTE: As before, machine pointer here refers to a pointer into the engine
    address space, not in the bytecode interpreter.
    """

    opcode = 0x0C
    mnemonic = "PUSHCB"


class PopAll(BytecodeOp):
    """
    Reset the stack to the initial state, clearing it.
    """

    opcode = 0x0F
    mnemonic = "POPALL"


class Add(BytecodeOp):
    """
    Removes the top two items from the stack, adds them, then pushes the result
    onto the stack.
    """

    opcode = 0x10
    mnemonic = "ADD"


class Subtract(BytecodeOp):
    """
    Removes the top two items from the stack, subtracts the second item from
    the first, then pushes the result onto the stack.
    """

    opcode = 0x11
    mnemonic = "SUB"


class Multiply(BytecodeOp):
    """
    Removes the top two items from the stack, multiplies them, then pushes the
    result onto the stack. The result is truncated to one word.
    """

    opcode = 0x12
    mnemonic = "MUL"


class Divide(BytecodeOp):
    """
    Removes the top two items from the stack, divides the second item by the
    first, then pushes the result onto the stack.

    NOTE: This is implemented in terms of x86 IDIV, so the result is truncated
    toward zero.
    """

    opcode = 0x13
    mnemonic = "DIV"


class Modulus(BytecodeOp):
    """
    Removes the top two items from the stack, divides the second item by the
    first, then pushes the remainder onto the stack (AKA modular division).
    """

    opcode = 0x14
    mnemonic = "MOD"


class LogicalAnd(BytecodeOp):
    """
    Removes the top two items from the stack, and if either item is zero,
    pushes a zero onto the stack. Otherwise, pushes -1 (0xFFFFFFFF).
    """

    opcode = 0x15
    mnemonic = "AND.L"


class LogicalOr(BytecodeOp):
    """
    Removes the top two items from the stack, and if both items are zero,
    pushes a zero onto the stack. Otherwise, pushes -1 (0xFFFFFFFF).
    """

    opcode = 0x16
    mnemonic = "OR.L"


class BitwiseAnd(BytecodeOp):
    """
    Removes the top two items from the stack, performs the bitwise AND of the
    two items, and pushes the result onto the stack.
    """

    opcode = 0x17
    mnemonic = "AND"


class BitwiseOr(BytecodeOp):
    """
    Removes the top two items from the stack, performs the bitwise OR of the
    two items, and pushes the result onto the stack.
    """

    opcode = 0x18
    mnemonic = "OR"


class BitwiseXor(BytecodeOp):
    """
    Removes the top two items from the stack, performs the bitwise exclusive-OR
    of the two items, and pushes the result onto the stack.
    """

    opcode = 0x19
    mnemonic = "XOR"


class Negate(BytecodeOp):
    """
    Negates (inverts the sign) of the item at the top of the stack,
    equivalent mathematically to multiplying it by -1.
    """

    opcode = 0x1A
    mnemonic = "NEG"


class BitwiseNot(BytecodeOp):
    """
    Performs a bitwise NOT on the item at the top of the stack.
    """

    opcode = 0x1B
    mnemonic = "NOT"


class ShiftLeft(BytecodeOp):
    """
    Removes the top two items from the stack, shifts the value of the first
    item left by the number of times given by the second item, then pushes the
    result onto the stack.
    """

    opcode = 0x1C
    mnemonic = "SHL"


class ArithmeticShiftRight(BytecodeOp):
    """
    Removes the top two items from the stack, shifts the value of the first
    item right by the number of times given by the second item, then pushes the
    result onto the stack. This is an arithmetic (sign-extending) right shift.
    """

    opcode = 0x1D
    mnemonic = "SHR"


class CompareZero(BytecodeOp):
    """
    Removes the top item from the stack. If it is equal to zero, pushes
    -1 (0xFFFFFFFF) onto the stack. Otherwise 0 is pushed onto the stack.
    """

    opcode = 0x1E
    mnemonic = "CMP.Z"


class Compare(BytecodeOp):
    """
    Removes the top two items from the stack. If they are equal, pushes
    -1 (0xFFFFFFFF) onto the stack. Otherwise 0 is pushed onto the stack.
    """

    opcode = 0x20
    mnemonic = "CMP"


class CompareNotEqual(BytecodeOp):
    """
    Removes the top two items from the stack. If they are NOT equal, pushes
    -1 (0xFFFFFFFF) onto the stack. Otherwise 0 is pushed onto the stack.
    """

    opcode = 0x21
    mnemonic = "CMP.NE"


class CompareGreaterEqual(BytecodeOp):
    """
    Removes the top two items from the stack. If they are equal or the first
    item is greater than the second, pushes -1 (0xFFFFFFFF) onto the stack.
    Otherwise 0 is pushed onto the stack.
    """

    opcode = 0x22
    mnemonic = "CMP.GE"


class CompareLessEqual(BytecodeOp):
    """
    Removes the top two items from the stack. If they are equal or the first
    item is less than the second, pushes -1 (0xFFFFFFFF) onto the stack.
    Otherwise 0 is pushed onto the stack.
    """

    opcode = 0x23
    mnemonic = "CMP.LE"


class CompareGreaterThan(BytecodeOp):
    """
    Removes the top two items from the stack. If the first item is greater than
    the second, pushes -1 (0xFFFFFFFF) onto the stack. Otherwise 0 is pushed
    onto the stack.
    """

    opcode = 0x24
    mnemonic = "CMP.GT"


class CompareLessThan(BytecodeOp):
    """
    Removes the top two items from the stack. If the first item is less than
    the second, pushes -1 (0xFFFFFFFF) onto the stack. Otherwise 0 is pushed
    onto the stack.
    """

    opcode = 0x25
    mnemonic = "CMP.LT"


class IncrementBlk0(BytecodeOp):
    """
    Increments the word at index `slot` in data block 0 by 1.
    """

    __match_args__ = ('slot',)

    opcode = 0x28
    operand_format = "B"
    mnemonic = "INC.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class DecrementBlk0(BytecodeOp):
    """
    Decrements the word at index `slot` in data block 0 by 1.
    """

    __match_args__ = ('slot',)

    opcode = 0x29
    operand_format = "B"
    mnemonic = "DEC.BLK0"

    @property
    def slot(self) -> int:
        return self.operands[0]


class IncrementBlk1(BytecodeOp):
    """
    Increments the word at index `slot` in data block 1 by 1.
    """

    __match_args__ = ('slot',)

    opcode = 0x2A
    operand_format = "B"
    mnemonic = "INC.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class DecrementBlk1(BytecodeOp):
    """
    Decrements the word at index `slot` in data block 1 by 1.
    """

    __match_args__ = ('slot',)

    opcode = 0x2B
    operand_format = "B"
    mnemonic = "DEC.BLK1"

    @property
    def slot(self) -> int:
        return self.operands[0]


class JumpUnconditional(BytecodeOp):
    """
    Moves the program counter of the bytecode interpreter to `target` relative
    to the start of the bytecode program.
    """

    __match_args__ = ('target',)

    opcode = 0x30
    operand_format = "<I"
    mnemonic = "JMP"

    @property
    def target(self) -> int:
        return self.operands[0]


class JumpZero(BytecodeOp):
    """
    If the top item in the stack is zero, moves the program counter of the
    bytecode interpreter to `target` relative to the start of the bytecode
    program. Otherwise, execution continues as normal. The stack is
    not modified.
    """

    __match_args__ = ('target',)

    opcode = 0x31
    operand_format = "<I"
    mnemonic = "JZ"

    @property
    def target(self) -> int:
        return self.operands[0]


class JumpNotZero(BytecodeOp):
    """
    If the top item in the stack is not zero, moves the program counter of
    the bytecode interpreter to `target` relative to the start of the bytecode
    program. Otherwise, execution continues as normal. The stack is
    not modified.
    """

    __match_args__ = ('target',)

    opcode = 0x32
    operand_format = "<I"
    mnemonic = "JNZ"

    @property
    def target(self) -> int:
        return self.operands[0]


class Unknown3(BytecodeOp):
    """
    It is not currently known what this opcode does.
    TODO: Figure that out.
    """

    __match_args__ = ('op0',)

    opcode = 0x33
    operand_format = "B"
    mnemonic = "UNK.3"

    @property
    def op0(self) -> int:
        return self.operands[0]


class Unknown4(BytecodeOp):
    """
    It is not currently known what this opcode does.
    TODO: Figure that out.
    """

    __match_args__ = ('op0',)

    opcode = 0x34
    operand_format = "<I"
    mnemonic = "UNK.4"

    @property
    def op0(self) -> int:
        return self.operands[0]


class Unknown5(BytecodeOp):
    """
    It is not currently known what this opcode does.
    It seems to be some sort of conditional relative jump?
    TODO: Figure that out.
    """

    __match_args__ = ('op0', 'op1', 'op2', 'op3')

    opcode = 0x35
    operand_format = "BBBB"
    mnemonic = "UNK.5"

    @property
    def op0(self) -> int:
        return self.operands[0]

    @property
    def op1(self) -> int:
        return self.operands[1]

    @property
    def op2(self) -> int:
        return self.operands[2]

    @property
    def op3(self) -> int:
        return self.operands[3]



class Pop(BytecodeOp):
    """
    Pops the top `num_slots` slots from the stack and saves them into
    temporary storage.

    NOTE: Unlike the COPY ops, this *is* number of slots, NOT number of
    stack bttes.
    """

    __match_args__ = ('num_slots',)

    opcode = 0x38
    operand_format = "B"
    mnemonic = "POP"

    @property
    def num_slots(self) -> int:
        return self.operands[0]


class Test(BytecodeOp):
    """
    Appears to be unused in scripts; maybe a leftover?
    Takes the top item from the stack, and if the item is greater than 0, the
    carry flag is set. Otherwise the carry flag is cleared.
    """

    opcode = 0x39
    mnemonic = "TEST"


class SwitchScript(BytecodeOp):
    """
    Sets the program counter to the script address indicated by entry
    `entry_point` in the entry point table.
    TODO: Is this used to do function calls?
    """

    __match_args__ = ('entry_point',)

    opcode = 0x3B
    operand_format = "B"
    mnemonic = "SCR"

    @property
    def entry_point(self) -> int:
        return self.operands[0]


class PlaySoundHalfWord(BytecodeOp):
    """
    Plays the sound sample at index `sound_id` in the currently attached SBF.
    The operand is a 16-bit integer.
    """

    __match_args__ = ('sound_id',)

    opcode = 0x3D
    operand_format = "<H"
    mnemonic = "PLAY.H"

    @property
    def sound_id(self) -> int:
        return self.operands[0]


class PlaySoundByte(BytecodeOp):
    """
    Plays the sound sample at index `sound_id` in the currently attached SBF.
    The operand is an 8-bit integer.
    """

    __match_args__ = ('sound_id',)

    opcode = 0x3E
    operand_format = "B"
    mnemonic = "PLAY.B"

    @property
    def sound_id(self) -> int:
        return self.operands[0]


class RestartScript(BytecodeOp):
    """
    Sets the interpreter's program counter back to the beginning of the script.
    """

    opcode = 0x3F
    mnemonic = "SCR.RES"


class SoundCmd(BytecodeOp):
    """
    Executes the named command at index `command_id` in the script command
    table specified in this script file.
    """

    __match_args__ = ('command_id',)

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
    JumpZero,
    JumpNotZero,
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


class Interpreter:
    """
    Test interpreter for SCR bytecode
    """

    block0: bytearray
    block1: bytearray

    pc: int
    entry_points: list[int]
    stack: list[int] = []
    script: bytes
    cmd_list: list[str]

    def __init__(self, block0_size: int, block1_size: int, ip: int, entry_points: list[int], script: bytes, cmd_list: list[str]):
        self.block0 = bytearray(block0_size)
        self.block1 = bytearray(block1_size)
        self.pc = ip
        self.entry_points = entry_points
        self.script = script
        self.cmd_list = cmd_list

    def _stack_pop(self, n) -> list[int]:
        stack_values = []
        assert n > 0, "invalid stack pop length"

        for _ in range(n):
            stack_values.append(self.stack.pop())

        # stack args are left-to-right so we need to reverse
        stack_values.reverse()
        return stack_values

    @staticmethod
    def _heap_write(fmt: str, block: bytearray, index: int, value: int):
        start = index
        end = index + struct.calcsize(fmt)
        block[start:end] = struct.pack(fmt, value)

    @staticmethod
    def _heap_read(fmt: str, block: bytearray, index: int) -> int:
        start = index
        end = index + struct.calcsize(fmt)
        v_bs = block[start:end]
        return struct.unpack(fmt, v_bs)[0]

    def _exec_op(self, op: BytecodeOp):
        ctrl_flow_affected = False

        match op:
            case Nop():
                pass
            case InvalidOp(opcode):
                raise ValueError(f"illegal opcode {opcode:02X}")
            case PushByteImmediate(immediate) | PushWordImmediate(immediate):
                self.stack.append(immediate)
            case PopWordBlk0(slot):
                value, = self._stack_pop(1)
                v_bs = self._heap_write("<i", self.block0, slot, value)
            case PopWordBlk1(slot):
                value, = self._stack_pop(1)
                v_bs = self._heap_write("<i", self.block1, slot, value)
            case PushWordBlk0(slot):
                value = self._heap_read("<i", self.block0, slot)
                self.stack.append(value)
            case op:
                raise NotImplementedError(f"TODO: implement {op.mnemonic}")

        # most ops do not alter the program counter so we do that here unless
        # an op specifically indicates it does so
        if not ctrl_flow_affected:
            self.pc += op.operands_len + 1

    def step(self):
        if have_debug(logger):
            logger.debug(f"IP:\t0x{self.pc:08X}")
        opcode = self.script[self.pc]
        op_cls = OPCODE_LOOKUP.get(opcode)
        if op_cls is None:
            op = InvalidOp(opcode)
        else:
            operand_idx_base = self.pc + 1
            operands = self.script[operand_idx_base:operand_idx_base + op_cls.operands_len]
            if len(operands) == 0 and op_cls.operands_len != 0:
                logger.error(f"read past end of script while parsing operands for {op_cls!r}")
                raise IndexError(f"indexed past end of script")
            op = op_cls(operands)

        if have_debug(logger):
            logger.debug(f"Decoded op as {op!r}")

        self._exec_op(op)

    def run(self):
        while True:
            self.step()


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
