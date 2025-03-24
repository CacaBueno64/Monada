from compression import *
from struct import pack, unpack, unpack_from, Struct
from io import BytesIO
from enum import Enum
import re

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
            nameOffset = unpack("<I", data.read(4))[0]
        elif length == PointerLength.Long:
            nameOffset = unpack("<L", data.read(8))[0]
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
            function.instructionOffset,
            function.instructionEndOffset - function.instructionOffset,
            function.jumpOffset,
            function.jumpCount,
            function.parameterCount,
            function.localCount,
            function.objectCount,
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
            instruction.returnParameter,
            instruction.instructionType,
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
    return text.decode("shift-jis")


def CreateValueExpression(value, argumentType, rawArgumentType = -1):
    output = ""
    if argumentType == ScriptArgumentType.Variable:
        if value >= 0 and value <= 999:
            output += f"unk{value}"
        elif value >= 1000 and value <= 1999:
            output += f"local{value - 1000}"
        elif value >= 2000 and value <= 2999:
            output += f"object{value - 2000}"
        elif value >= 3000 and value <= 3999:
            output += f"param{value - 3000}"
        elif value >= 4000 and value <= 4999:
            output += f"global{value - 4000}"
    else:
        if argumentType == ScriptArgumentType.Int:
            output += f"{value}"
        elif argumentType == ScriptArgumentType.StringHash:
            output += f"{value}"
        elif argumentType == ScriptArgumentType.Float:
            output += f"{value}"
        elif argumentType == ScriptArgumentType.String:
            output += f'"{value}"'
    
    if rawArgumentType >= 0:
        output += f"<{rawArgumentType}>"
    
    return output

def CreateArrayIndexExpression(arrayVariable, indexes):
    if type(arrayVariable) == ScriptArgument:
        arrayVariable = CreateValueExpression(arrayVariable.Value, arrayVariable.Type, arrayVariable.RawArgumentType)
    
    output = arrayVariable
    for index in indexes:
        output += f"[{CreateValueExpression(index.Value, index.Type, index.RawArgumentType)}]"
    
    return output

def CreateGotoStatement(instruction, script):
    argument = script.Arguments[instruction.ArgumentIndex]
    output = f"goto {CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)}"
    return output

def to_txt(filepath, script):
    out = open(filepath, "wt")
    
    t = 0 # indentation level
    
    for function in script.Functions:
        #function = script.Functions[7]
        # function declaration
        out.write(f"def {function.Name}(")
        # function params
        for i in range(function.ParameterCount):
            out.write(f"param{i}")
            out.write(", ") if i != function.ParameterCount -1 else 0
        out.write("):\n")

        # body function
        t = 1

        jumpLookup = {}
        jumps = script.Jumps[function.JumpIndex:function.JumpIndex + function.JumpCount]
        for jump in jumps:
            jumpLookup[jump.InstructionIndex] = []
        for jump in jumps:
            jumpLookup[jump.InstructionIndex].append(jump)
        if function.InstructionCount != 0:
            for i in range(function.InstructionIndex, function.InstructionIndex + function.InstructionCount):
                instruction = script.Instructions[i]

                if jumpLookup.get(i):
                    for jump in jumpLookup[i]:
                        out.write(f'"{jump.Name}":\n')

                if instruction.Type == 10:
                    out.write("\t" * t + "yield\n")
                elif instruction.Type == 11:
                    out.write("\t" * t + "return ")
                    if instruction.ArgumentCount > 0:
                        argument = script.Arguments[instruction.ArgumentIndex]
                        out.write(f"{CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)}\n")
                    else:
                        out.write("\n")
                elif instruction.Type == 12:
                    out.write("\t" * t + "exit()\n")
                elif instruction.Type in (30, 33):
                    out.write("\t" * t + "if ")
                    if instruction.Type == 33:
                        out.write("not ")
                    argument = script.Arguments[instruction.ArgumentIndex + 1]
                    out.write(f"{CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)}")
                    out.write(f" {CreateGotoStatement(instruction, script)}\n")
                elif instruction.Type == 31:
                    out.write("\t" * t + f"{CreateGotoStatement(instruction, script)}\n")
                elif instruction.Type in (240, 241):
                    returnValue = CreateValueExpression(instruction.ReturnParameter, ScriptArgumentType.Variable)
                    value = returnValue
                    if instruction.ArgumentCount > 0:
                        value = CreateArrayIndexExpression(
                            returnValue, script.Arguments[instruction.ArgumentIndex:instruction.ArgumentIndex + instruction.ArgumentCount])
                    out.write("\t" * t + f"{value}")
                    if instruction.Type == 240:
                        out.write("++\n")
                    elif instruction.Type == 241:
                        out.write("--\n")
                else:
                    leftValue = CreateValueExpression(instruction.ReturnParameter, ScriptArgumentType.Variable)
                    left = leftValue
                    if instruction.Type in (100, 250, 251, 252, 253, 254, 260, 261, 262, 270, 271):
                        if instruction.ArgumentCount > 1:
                            indexes3 = script.Arguments[
                                instruction.ArgumentIndex + 1:(instruction.ArgumentIndex + 1) + instruction.ArgumentCount - 1]
                            left = CreateArrayIndexExpression(leftValue, indexes3)
                    right = ""
                    equalsOperator = "="
                    argument = script.Arguments[instruction.ArgumentIndex]
                    if instruction.Type == 100:
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type in (110, 112, 120):
                        value = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                        if instruction.Type == 110:
                            right = f"~{value}"
                        elif instruction.Type == 112:
                            right = f"-{value}"
                        elif instruction.Type == 120:
                            right = f"not {value}"
                    elif instruction.Type in (121, 122):
                        argument1 = script.Arguments[instruction.ArgumentIndex + 1]
                        lleft = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                        rright = CreateValueExpression(argument1.Value, argument1.Type, argument1.RawArgumentType)
                        if instruction.Type == 121:
                            right = f"{lleft} and {rright}"
                        elif instruction.Type == 122:
                            right = f"{lleft} or {rright}"
                    elif instruction.Type in (130, 131, 132, 133, 134, 135, 140, 141, 150, 151, 152, 153, 154, 160, 161, 162, 170, 171):
                        lleft = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                        if instruction.Type == 140:
                            right = f"{lleft} + {CreateValueExpression(1, ScriptArgumentType.Int)}"
                        elif instruction.Type == 141:
                            right = f"{lleft} - {CreateValueExpression(1, ScriptArgumentType.Int)}"
                        argument1 = script.Arguments[instruction.ArgumentIndex + 1]
                        rright = CreateValueExpression(argument1.Value, argument1.Type, argument1.RawArgumentType)
                        if instruction.Type == 130:
                            right = f"{lleft} == {rright}"
                        elif instruction.Type == 131:
                            right = f"{lleft} != {rright}"
                        elif instruction.Type == 132:
                            right = f"{lleft} >= {rright}"
                        elif instruction.Type == 133:
                            right = f"{lleft} <= {rright}"
                        elif instruction.Type == 134:
                            right = f"{lleft} > {rright}"
                        elif instruction.Type == 135:
                            right = f"{lleft} < {rright}"
                        elif instruction.Type == 150:
                            right = f"{lleft} + {rright}"
                        elif instruction.Type == 151:
                            right = f"{lleft} - {rright}"
                        elif instruction.Type == 152:
                            right = f"{lleft} * {rright}"
                        elif instruction.Type == 153:
                            right = f"{lleft} / {rright}"
                        elif instruction.Type == 154:
                            right = f"{lleft} % {rright}"
                        elif instruction.Type == 160:
                            right = f"{lleft} & {rright}"
                        elif instruction.Type == 161:
                            right = f"{lleft} | {rright}"
                        elif instruction.Type == 162:
                            right = f"{lleft} ^ {rright}"
                        elif instruction.Type == 170:
                            right = f"{lleft} << {rright}"
                        elif instruction.Type == 171:
                            right = f"{lleft} >> {rright}"
                    elif instruction.Type == 250:
                        equalsOperator = "+="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 251:
                        equalsOperator = "-="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 252:
                        equalsOperator = "*="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 253:
                        equalsOperator = "/="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 254:
                        equalsOperator = "%="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 260:
                        equalsOperator = "&="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 261:
                        equalsOperator = "|="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 262:
                        equalsOperator = "^="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 270:
                        equalsOperator = "<<="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 271:
                        equalsOperator = ">>="
                        right = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type in (511, 512, 513):
                        print("OH MY GOD A CAST VALUE EXPRESSION")
                        pass
                        #castValue = CreateValueExpression(argument.Value, argument.Type, argument.RawArgumentType)
                    elif instruction.Type == 523:
                        print("OH MY GOD A SWITCH STATEMENT")
                        pass
                    elif instruction.Type == 530:
                        print("OH MY GOD A 'new' KEYWORD")
                        pass
                    elif instruction.Type == 531:
                        indexes = script.Arguments[
                                instruction.ArgumentIndex + 1:(instruction.ArgumentIndex + 1) + instruction.ArgumentCount - 1]
                        right = CreateArrayIndexExpression(argument, indexes)
                    else: # Function calls (WIP)
                        pass
                        #identifier = ""
                        #if not (instruction.Type != 20 or instruction.ArgumentCount <= 0):
                        #    identifier = str(script.Arguments[instruction.ArgumentIndex].Value)
                    out.write("\t" * t + f"{left} {equalsOperator} {right}\n")

            instructionEndIndex = function.InstructionIndex + function.InstructionCount
            if jumpLookup.get(instructionEndIndex):
                for jump in jumpLookup[instructionEndIndex]:
                    out.write(f'"{jump.Name}":\n')

            out.write("\n")
    
    out.close()

with open("./filepath.xq", "rb") as file:
    script = open_xseq(BytesIO(file.read()))
    to_txt("./filepath.txt", script)
