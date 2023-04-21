import idc
import idautils
import ida_bytes
import ida_nalt
import idaapi

import ctypes


class AddrInfoStruct(ctypes.Structure):
    _fields_ = [
        ("originalAddr", ctypes.c_ulong),
        ("newOffset", ctypes.c_ushort)
    ]

    def __getitem__(self, key):
        if key == 'originalAddr':
            return self.originalAddr
        elif key == 'newOffset':
            return self.newOffset
        else:
            raise KeyError(f'Invalid key: {key}')


shellcodeData = bytearray()
funcInfo_map = {}
varInfo_map = {}
importInfo_map = {}
iatInfo_map = {}
relocTable = []
fileOffset = 0
dllName = ""


def addr_align():
    global fileOffset

    if fileOffset % 4 != 0:
        align = 4 - fileOffset % 4
        shellcodeData.extend(b'\x00' * align)
        fileOffset += align


def searchValue(addr, value):
    i = 0
    while ida_bytes.get_dword(addr + i) != value:
        i = i + 1

    return addr + i


def patchDword(index, value):
    dword_bytes = struct.pack('<I', value)
    shellcodeData[index:index + 4] = dword_bytes


def replaceMarkValue(markValue, replaceValue):
    binary_str = struct.pack(">I", markValue)
    hex_str = binary_str.hex()

    for key, value in funcInfo_map.items():
        func_items = FuncItems(key)
        for addr in func_items:
            str = idc.generate_disasm_line(addr, 0)
            if hex_str in str and "mov" in str:
                patchDword(idaAddr2FileOffset(searchValue(addr, markValue)), replaceValue)
                return


def memset(index, value, size):
    for i in range(size):
        shellcodeData[i + index] = value


def idaAddr2FileOffset(idaAddr):
    func = ida_funcs.get_func(idaAddr)
    start_addr = func.start_ea

    if start_addr not in funcInfo_map:
        return 0

    return funcInfo_map[start_addr]["newOffset"] + (idaAddr - funcInfo_map[start_addr]["originalAddr"])


def getDwordValue(vaule):
    return ctypes.c_uint32(vaule).value


def get_wide_str_length(ea):
    length = 0
    while ida_bytes.get_wide_byte(ea + length * 2) != 0:
        length += 1
    return length


def saveFuncData(funcAddr):
    global fileOffset

    func = ida_funcs.get_func(funcAddr)
    start_addr = func.start_ea
    end_addr = func.end_ea

    if start_addr in funcInfo_map:
        return
    funcInfo_map[start_addr] = AddrInfoStruct(start_addr, fileOffset)

    fileOffset += (end_addr - start_addr)

    shellcodeData.extend(get_bytes(start_addr, end_addr - start_addr))

    func_items = FuncItems(start_addr)
    for addr in func_items:
        str = idc.generate_disasm_line(addr, 0)
        if (ida_bytes.get_byte(addr) == 0xE8 or "offset StartAddress" in str) and ("security_check_cookie" not in str):
            if "offset StartAddress" in str:
                callFuncAddr = ida_bytes.get_dword(addr + 1)
            else:
                callFuncAddr = ida_bytes.get_dword(addr + 1) + addr + 5
            saveFuncData(getDwordValue(callFuncAddr))


def fixE8CallOffset():
    for key, value in funcInfo_map.items():
        func_items = FuncItems(key)
        for addr in func_items:
            str = idc.generate_disasm_line(addr, 0)
            if (ida_bytes.get_byte(addr) == 0xE8 or "offset StartAddress" in str) and ("security_check_cookie" not in str):
                callFuncAddr = ida_bytes.get_dword(addr + 1) + addr + 5
                if "offset StartAddress" in str:
                    callFuncAddr = ida_bytes.get_dword(addr + 1)
                callFuncAddr = getDwordValue(callFuncAddr)

                if callFuncAddr in funcInfo_map:
                    e8CallOffset = funcInfo_map[callFuncAddr]["newOffset"] - (idaAddr2FileOffset(addr) + 5)
                    if "offset StartAddress" in str:
                        e8CallOffset = funcInfo_map[callFuncAddr]["newOffset"]
                        relocTable.append(idaAddr2FileOffset(addr + 1))
                else:  # 处理特殊情况:在同一个函数中跳转指令没有用jcc实现，而是用的call指令
                    func = ida_funcs.get_func(callFuncAddr)
                    fixOffset = funcInfo_map[func.start_ea]["newOffset"] + (
                                callFuncAddr - funcInfo_map[func.start_ea]["originalAddr"])
                    e8CallOffset = fixOffset - (idaAddr2FileOffset(addr) + 5)
                patchDword(idaAddr2FileOffset(addr + 1), getDwordValue(e8CallOffset))
    print("--------------fixE8CallOffset finish!--------------")


def deleteSecurityCode():
    for key, value in funcInfo_map.items():
        func_items = FuncItems(key)
        for addr in func_items:
            str = idc.generate_disasm_line(addr, 0)
            if "security_check_cookie" in str:
                memset(idaAddr2FileOffset(addr - 5), 0x90, 10)
            elif "security_cookie" in str:
                memset(idaAddr2FileOffset(addr), 0x90, 10)
    print("--------------deleteSecurityCode finish!--------------")


def saveVarData(addr, case):
    global fileOffset

    for i in range(5):
        value = get_operand_value(addr, i)
        if value < 0xf0000000 and value > 0x1000: #这里有的操作数会为负数，需要处理下
            break
    value = getDwordValue(value)

    if value in varInfo_map:
        return

    addr_align()

    varInfo_map[value] = AddrInfoStruct(value, fileOffset)

    for x in XrefsTo(value, flags=0):
        relocOffset = idaAddr2FileOffset(searchValue(x.frm, value))
        if relocOffset != 0:
            patchDword(relocOffset, getDwordValue(fileOffset))
            relocTable.append(relocOffset)

    if case == -1:
        strLength = 0
        if ida_nalt.get_str_type(value) != ida_nalt.STRTYPE_C:
            strLength = (get_wide_str_length(value) + 1) * 2
        else:
            str_content = idc.get_strlit_contents(value)
            strLength = len(str_content) + 1
        shellcodeData.extend(get_bytes(value, strLength))
        fileOffset += strLength
    elif case == 5:
        i = 0
        length = 0
        while i < 5:
            addr = next_head(addr)
            str = idc.generate_disasm_line(addr, 0)
            if "movsw" in str:
                length += 2
            if "movsb" in str:
                length += 1
            i += 1
        while 1:
            addr = prev_head(addr)
            str = idc.generate_disasm_line(addr, 0)
            if "ecx" in str:
                ecxValue = get_operand_value(addr, 1)
                length += ecxValue * 4
                break
        shellcodeData.extend(get_bytes(value, length))
        fileOffset += length
    else:
        shellcodeData.extend(get_bytes(value, 4))
        fileOffset += 4


def copyVarToShellcode():
    for key, value in funcInfo_map.items():
        func_items = FuncItems(key)
        for addr in func_items:
            str = idc.generate_disasm_line(addr, 0)
            if " byte_" in str:
                saveVarData(addr, 1)
            elif " word_" in str:
                saveVarData(addr, 2)
            elif str.find("dword_") != -1:
                saveVarData(addr, 4)
            elif "offset StartAddress" in str:
                continue
            elif "offset" in str:
                if "mov     esi" in str:
                    saveVarData(addr, 5)
                else:
                    saveVarData(addr, -1)

    addr_align()
    print("--------------copyVarToShellcode finish!--------------")


def imp_cb(ea, name, ord):
    if name:
        importInfo_map[name] = {"dllName": dllName, "apiName": name, "flag": False, "addr": ea}
    return True


def enum_exported_dll_func():
    global dllName

    for i in range(idaapi.get_import_module_qty()):
        dllName = idaapi.get_import_module_name(i)
        idaapi.enum_import_names(i, imp_cb)


def generateIatStrToShellcode():
    global fileOffset, shellcodeData

    enum_exported_dll_func()
    replaceMarkValue(0x77777777, fileOffset)

    for key, value in funcInfo_map.items():
        func_items = FuncItems(key)
        for addr in func_items:
            str = idc.generate_disasm_line(addr, 0)
            if "call" in str and "ds:" in str:
                apiName = str[str.rfind(":") + 1:]

                if importInfo_map[apiName]["flag"] == False:
                    importInfo_map[apiName]["flag"] = True
                    if importInfo_map[apiName]["dllName"] not in iatInfo_map:
                        iatInfo_map[importInfo_map[apiName]["dllName"]] = []
                    iatInfo_map[importInfo_map[apiName]["dllName"]].append(importInfo_map[apiName]["apiName"])

    for key, value in iatInfo_map.items():
        shellcodeData += bytes(key, encoding="ascii")
        shellcodeData += bytearray('\x00\x2C', encoding="ascii")
        fileOffset += len(key) + 2
        for str in value:
            shellcodeData += bytes(str, encoding="ascii")
            shellcodeData += bytearray('\x00\x2C', encoding="ascii")
            fileOffset += len(str) + 2
        shellcodeData[fileOffset - 1] = 0x3B
    shellcodeData[fileOffset - 1] = 0x00

    addr_align()
    print("--------------generateIatStrToShellcode finish!--------------")


def generateIatTableAndFix():
    global fileOffset
    replaceMarkValue(0x66666666, fileOffset)

    for key, value in iatInfo_map.items():
        for apiName in value:
            iatInfo = importInfo_map[apiName]

            for x in XrefsTo(iatInfo["addr"], flags=0):
                func = ida_funcs.get_func(x.frm)
                if func == None or func.start_ea not in funcInfo_map:
                    continue

                relocOffset = idaAddr2FileOffset(searchValue(x.frm, iatInfo["addr"]))
                if relocOffset != 0:
                    patchDword(relocOffset, getDwordValue(fileOffset))  # 这是是不是不需要getDwordValue
                    relocTable.append(relocOffset)

            shellcodeData.extend(b'\x00' * 4)
            fileOffset += 4
    addr_align()
    print("--------------generateIatTableAndFix finish!--------------")


def generateRelocTable():
    global fileOffset, relocTable
    replaceMarkValue(0x99999999, fileOffset)

    relocTable = list(set(relocTable))
    for relocOffset in relocTable:
        shellcodeData.extend(struct.pack('<H', relocOffset))
        fileOffset += 2

    replaceMarkValue(0x88888888, fileOffset)
    addr_align()
    print("--------------generateRelocTable finish!--------------")


def outputShellcode():
    fileName = 'shellcode.txt'
    shellcodeTxt = "\""
    f = open(fileName, 'w')
    for index in range(fileOffset):
        shellcodeTxt += '\\x{:02x}'.format(shellcodeData[index])
    shellcodeTxt += "\""
    f.write(shellcodeTxt)
    f.close()

    fileName1 = 'shellcode.bin'
    f = open(fileName1, 'wb')
    f.write(shellcodeData)
    f.close()

    print("--------------outputShellcode finish!--------------")
    print("shellcode outputPath: %s\n%s" % (os.getcwd() + '\\' + fileName, os.getcwd() + '\\' + fileName1))
    print("shellcode length: 0x%x" % fileOffset)


def main(OEP):
    saveFuncData(OEP)
    print("--------------saveFuncData finish!--------------")

    fixE8CallOffset()

    deleteSecurityCode()

    copyVarToShellcode()

    generateIatStrToShellcode()

    generateIatTableAndFix()

    generateRelocTable()

    outputShellcode()

    return


if __name__ == '__main__':
    main(here())
