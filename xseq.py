from compression import *
from struct import pack, unpack, unpack_from, Struct
from io import BytesIO
from enum import Enum

class CompressionType(Enum):
    null = 0
    Level5_Lz10 = 1
    Level5_Huffman4Bit = 2
    Level5_Huffman8Bit = 3
    Level5_Rle = 4
    ZLib = 5
class PointerLength(Enum):
    Int = 0
    Long = 1
class ScriptArgumentType(Enum):
    Int = 0
    StringHash = 1
    Float = 2
    Variable = 3
    String = 4
    null = -1

class XseqHeader:
    strct = Struct("<4s hH Hh Hh Hh hH")
    def __init__(self, data):
        self.magic, \
        self.functionEntryCount, self.functionOffset, \
        self.jumpOffset, self.jumpEntryCount, \
        self.instructionOffset, self.instructionEntryCount, \
        self.argumentOffset, self.argumentEntryCount, \
        self.globalVariableCount, self.stringOffset = data
    
    def GetTableData(self):
        return (
            TableData(self.functionOffset << 2, self.functionEntryCount),
            TableData(self.jumpOffset << 2, self.jumpEntryCount),
            TableData(self.instructionOffset << 2, self.instructionEntryCount),
            TableData(self.argumentOffset << 2, self.argumentEntryCount),
            self.stringOffset << 2,
        )

class TableData:
    def __init__(self, offset, count):
        self.offset = offset
        self.count = count

class ScriptContainer:
    def __init__(self, data):
        self.FunctionTable, self.JumpTable, self.InstructionTable, self.ArgumentTable, \
        self.StringTable, self.GlobalVariableCount = data

class ScriptTable:
    def __init__(self, data):
        self.EntryCount, self.Stream = data
class ScriptStringTable:
    def __init__(self, data):
        self.Stream = data

class ScriptFunction:
    strct = "<%ds hh hh i hh"
    def __init__(self, data):
        self.Name, \
        self.InstructionIndex, self.InstructionCount, \
        self.JumpIndex, self.JumpCount, \
        self.ParameterCount, self.LocalCount, self.ObjectCount = data
class ScriptJump:
    strct = "<%ds h"
    def __init__(self, data):
        self.Name, \
        self.InstructionIndex = data
class ScriptInstruction:
    strct = Struct("<hhhh")
    def __init__(self, data):
        self.ArgumentIndex, \
        self.ArgumentCount, \
        self.ReturnParameter, \
        self.Type = data
class ScriptArgument:
    strct = "<i %s I"
    def __init__(self, data):
        self.RawArgumentType, \
        self.Type, \
        self.Value = data

class XseqFunction:
    strct = Struct("<l H hhhhhhh")
    def __init__(self, data):
        self.nameOffset, \
        self.crc16, \
        self.instructionOffset, \
        self.instructionEndOffset, \
        self.jumpOffset, \
        self.jumpCount, \
        self.localCount, \
        self.objectCount, \
        self.parameterCount = data
class XseqJump:
    strct = Struct("<l H h")
    def __init__(self, data):
        self.nameOffset, \
        self.crc16, \
        self.instructionIndex = data
class XseqInstruction:
    strct = Struct("<hhhhi")
    def __init__(self, data):
        self.argOffset, \
        self.argCount, \
        self.returnParameter, \
        self.instructionType, \
        self.zero0 = data
class XseqArgument:
    strct = Struct("<iI")
    def __init__(self, data):
        self.type, self.value = data

class ScriptFile:
    def __init__(self, data):
        self.Functions, \
        self.Jumps, \
        self.Instructions, \
        self.Arguments, \
        self.Length = data

def open_xseq(data):
    header = XseqHeader(unpack("<4s hH Hh Hh Hh hH", data.read(24)))
    if header.magic != b"XSEQ":
        raise ValueError(f"Wrong xq format, got: {header.magic}, expected: b'XSEQ'.")
    
    functionTable, jumpTable, instructionTable, argumentTable, stringOffset = \
        header.GetTableData()
    
    hasCompression = HasCompression(functionTable, jumpTable, instructionTable, argumentTable, stringOffset)
    
    container = ScriptContainer((
        ReadTable(data, functionTable, jumpTable.offset, hasCompression),
        ReadTable(data, jumpTable, instructionTable.offset, hasCompression),
        ReadTable(data, instructionTable, argumentTable.offset, hasCompression),
        ReadTable(data, argumentTable, stringOffset, hasCompression),
        ReadStringTable(data, stringOffset, hasCompression),
        header.globalVariableCount,
    ))
    
    tdpl, length = TryDetectPointerLength(container)
    if not tdpl: raise ValueError("Could not detect pointer length.")
    
    functions = ReadFunctions(container.FunctionTable, container.StringTable, length)
    jumps = ReadJumps(container.JumpTable, container.StringTable, length)
    instructions = ReadInstructions(container.InstructionTable, length)
    arguments = ReadArguments(container.ArgumentTable, instructions, container.StringTable, length)
    
    return ScriptFile((
        functions,
        jumps,
        instructions,
        arguments,
        length,
    ))

def ReadTable(data, tableData, nextOffset, hasCompression):
    data.seek(tableData.offset)
    if hasCompression:
        data = decompress(data.read(nextOffset - tableData.offset))
    else:
        data = data.read(nextOffset - tableData.offset)
    while len(data) % 4 != 0:
        data = data[:len(data) - 1]
    
    return ScriptTable((tableData.count, BytesIO(data)))

def ReadStringTable(data, offset, hasCompression):
    data.seek(offset)
    if hasCompression:
        data = BytesIO(decompress(data.read(len(data.getvalue()) - offset)))
    else:
        data = BytesIO(data.read(len(data.getvalue()) - offset))
    
    return ScriptStringTable((data))

def HasCompression(functionTable, jumpTable, instructionTable, argumentTable, stringOffset):
    for i in range(2):
        entrySize = GetFunctionEntrySize(PointerLength(i))
        if functionTable.count * entrySize != jumpTable.offset - functionTable.offset:
            continue
        entrySize = GetJumpEntrySize(PointerLength(i))
        if jumpTable.count * entrySize != instructionTable.offset - jumpTable.offset:
            continue
        entrySize = GetInstructionEntrySize(PointerLength(i))
        if instructionTable.count * entrySize != argumentTable.offset - instructionTable.offset:
            continue
        entrySize = etArgumentEntrySize(PointerLength(i))
        if argumentTable.count * entrySize != stringOffset - argumentTable.offset:
            continue
        return False
    return True

def TryDetectPointerLength(container):
    length = None
    for i in range(2):
        localLength = PointerLength(i)
        entrySize = GetFunctionEntrySize(localLength)
        if container.FunctionTable.EntryCount * entrySize != len(container.FunctionTable.Stream.getvalue()):
            continue
        entrySize = GetJumpEntrySize(localLength)
        if container.JumpTable.EntryCount * entrySize != len(container.JumpTable.Stream.getvalue()):
            continue
        entrySize = GetInstructionEntrySize(localLength)
        if container.InstructionTable.EntryCount * entrySize != len(container.InstructionTable.Stream.getvalue()):
            continue
        entrySize = GetArgumentEntrySize(localLength)
        if container.ArgumentTable.EntryCount * entrySize != len(container.ArgumentTable.Stream.getvalue()):
            continue
        length = localLength
        return True, length
    return False, length

def GetFunctionEntrySize(length):
    if length == PointerLength.Int: return 0x14
    elif length == PointerLength.Long: return 0x18
def GetJumpEntrySize(length):
    if length == PointerLength.Int: return 0x8
    elif length == PointerLength.Long: return 0x10
def GetInstructionEntrySize(length):
    if length == PointerLength.Int: return 0xC
    elif length == PointerLength.Long: return 0x10
def GetArgumentEntrySize(length):
    if length == PointerLength.Int: return 0x8
    elif length == PointerLength.Long: return 0x10

def ReadFunctions(functionTable, StringTable, length):
    result = []
    data = functionTable.Stream
    entryCount = functionTable.EntryCount
    
    for i in range(entryCount):
        nameOffset = 0
        if length == PointerLength.Int:
            nameOffset == unpack("<I", data.read(4))[0]
        elif length == PointerLength.Long:
            nameOffset == unpack("<L", data.read(8))[0]
        else:
            raise ValueError(f"Unknown pointer length {length}.")
        
        result.append(XseqFunction((
            nameOffset,
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
            unpack("<H", data.read(2))[0],
        )))
    
    return CreateFunctions(result, StringTable)

functionCache = {}
def CreateFunctions(functions, stringTable):
    def CreateFunction(function, stringtable):
        name = ""
        if stringtable:
            stringtable.Stream.seek(function.nameOffset)
            name = read_str(stringtable.Stream)
            
            functionNames = functionCache.setdefault(function.crc16, set())
        
        return ScriptFunction((
            name,
            function.jumpOffset,
            function.jumpCount,
            function.instructionOffset,
            function.instructionEndOffset - function.instructionOffset,
            function.parameterCount,
            function.localCount,
            function.parameterCount,
        ))
    
    result = []
    for function in sorted(functions, key=lambda x: (x.instructionOffset, x.instructionEndOffset, x.crc16)):
        result.append(CreateFunction(function, stringTable))
    
    return result

def ReadJumps(jumpTable, stringTable, length):
    result = []
    data = jumpTable.Stream
    entryCount = jumpTable.EntryCount
    
    for i in range(entryCount):
        if length == PointerLength.Int:
            result.append(XseqJump((
                unpack("<i", data.read(4))[0],
                unpack("<H", data.read(2))[0],
                unpack("<h", data.read(2))[0],
            )))
        elif length == PointerLength.Long:
            result.append(XseqJump((
                unpack("<l", data.read(8))[0],
                unpack("<H", data.read(2))[0],
                unpack("<h", data.read(2))[0],
            )))
            data.seek(data.tell() + 4)
    
    return CreateJumps(result, stringTable)

jumpCache = {}
def CreateJumps(jumps, stringTable):
    def CreateJump(jump, stringtable):
        name = ""
        if stringtable:
            stringtable.Stream.seek(jump.nameOffset)
            name = read_str(stringtable.Stream)
            
            jumpNames = jumpCache.setdefault(jump.crc16, set())
        
        return ScriptJump((
            name,
            jump.instructionIndex,
        ))
    
    result = []
    for jump in jumps:
        result.append(CreateJump(jump, stringTable))
    
    return result

def ReadInstructions(instructionTable, length):
    result = []
    data = instructionTable.Stream
    entryCount = instructionTable.EntryCount
    
    for i in range(entryCount):
        result.append(XseqInstruction((
            unpack("<h", data.read(2))[0],
            unpack("<h", data.read(2))[0],
            unpack("<h", data.read(2))[0],
            unpack("<h", data.read(2))[0],
            unpack("<i", data.read(4))[0] if length == PointerLength.Int else \
            unpack("<l", data.read(8))[0]
        )))
    
    return CreateInstructions(result)

def CreateInstructions(instructions):
    def CreateInstruction(instruction):
        return ScriptInstruction((
            instruction.argOffset,
            instruction.argCount,
            instruction.instructionType,
            instruction.returnParameter,
        ))
    
    result = []
    
    for instruction in instructions:
        result.append(CreateInstruction(instruction))
    
    return result

def ReadArguments(argumentTable, instructions, stringTable, length):
    result = []
    data = argumentTable.Stream
    entryCount = argumentTable.EntryCount
    
    for i in range(entryCount):
        if length == PointerLength.Int:
            result.append(XseqArgument((
                unpack("<i", data.read(4))[0],
                unpack("<I", data.read(4))[0],
            )))
        elif length == PointerLength.Long:
            _type = unpack("<i", data.read(4))[0],
            data.read(4)
            value = unpack("<I", data.read(4))[0],
            data.read(4)
            result.append(XseqArgument((
                _type, value
            )))
    
    return CreateArguments(result, instructions, stringTable)

def CreateArguments(arguments, instructions, stringTable):
    def CreateArgument(argument, instructionType, argumentIndex, stringtable):
        rawType = -1
        _type: ScriptArgumentType = None
        value: int = None
        
        if argument.type == 1:
            _type = ScriptArgumentType.Int
            value = argument.value
        elif argument.type == 2:
            _type = ScriptArgumentType.StringHash
            value = argument.value
            if argumentIndex != 0:
                names = functionCache.get(argument.value) or jumpCache.get(argument.value)
                if names:
                    value = next(iter(names))
            if instructionType == 20:
                names = functionCache.get(argument.value)
                if names:
                    value = next(iter(names))
            if instructionType == 30:
                names = jumpCache.get(argument.value)
                if names:
                    value = next(iter(names))
            if instructionType == 31:
                names = jumpCache.get(argument.value)
                if names:
                    value = next(iter(names))
            if instructionType == 33:
                names = jumpCache.get(argument.value)
                if names:
                    value = next(iter(names))
        elif argument.type == 3:
            _type = ScriptArgumentType.Float
            value = unpack("<f", pack("<I", argument.value))[0]
        elif argument.type == 4:
            _type = ScriptArgumentType.Variable
            value = argument.value
        elif argument.type in (24, 25):
            if stringtable.Stream:
                stringtable.Stream.seek(argument.value)
            if argument.type != 24:
                rawType = argument.type
            _type = ScriptArgumentType.String
            value = read_str(stringtable.Stream) if stringtable.Stream else ""
        
        return ScriptArgument((
            rawType,
            _type,
            value,
        ))
    
    result = [ScriptArgument] * len(arguments)
    
    instructionTypes = [tuple] * len(arguments)
    for instruction in instructions:
        for i in range(instruction.ArgumentCount):
            instructionTypes[instruction.ArgumentIndex + i] = (instruction.Type, i)
    
    for i, argument in enumerate(arguments):
        instructionType, argumentIndex = instructionTypes[i]
        result[i] = CreateArgument(argument, instructionType, argumentIndex, stringTable)
    
    return result

def read_str(data):
    text = b""
    while True:
        char = unpack("<1s", data.read(1))[0]
        if char == b"\x00":
            break
        text += char
    return text

with open("./sav.xq", "rb") as file:
    open_xseq(BytesIO(file.read()))