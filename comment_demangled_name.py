'''
Iterate over all instructions in all functions
For each call instruction, if the operand is a mangled name, add demangled name
as a comment
'''

import idaapi
import idc

for function_ea in idautils.Functions():
        for insn in idautils.FuncItems(function_ea):
            dis = idc.GetDisasm(insn)
            mnem = dis.split(' ', 1)[0]
            if mnem == 'call':
                target_ea = idc.GetOperandValue(insn, 0)
                target_name = idaapi.get_func_name(target_ea)
                demangled_name = idc.Demangle(target_name,
                    idc.GetLongPrm(idc.INF_SHORT_DN))
                if demangled_name is not None:
                    idc.MakeComm(insn, demangled_name)
