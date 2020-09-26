from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_form_class

import capstone
from capstone import CS_ARCH_ARM, CS_MODE_THUMB

import os
import linecache

# This file is a hodge-podge assembled from examples found in the pyelftools 
# and capstone documentation.

def ELF(fname):
    return ELFFile(open(fname, 'rb'))

def sections(elf):
    # Pyelftools reports a NullSection as first section.
    # Not present in the output from readelf.
    return [s for s in elf.iter_sections() if s.name]

def print_sizes(elf):
    """Print sections sorted by size."""
    for s in sorted(sections(elf), key=lambda x: x.data_size, reverse=True):
        print('{:<20}  {:>10,}'.format(s.name, s.data_size))

def DWARF(elf):
    return elf.get_dwarf_info()

def decode_file_line(dwarfinfo, address):
    """ Walk line program tables to find file/line for a given address."""

    # A line table is a matrix organized in increasing addresses.
    # Rows where fname, line, col and discriminator are identical with that of
    # its predecessor are omitted.
    #
    # These rows will return (70,16) for 0x800_01f8. Last row.
    # 0x080001f8  [  67,12] ET
    # 0x080001f8  [  70,16] NS
    # 0x080001f8  [  71, 5] NS
    # 0x080001f8  [   8,13] NS
    # 0x080001f8  [  11, 5] NS
    # 0x080001f8  [  70,16]
    #
    # These lines will return (11, 5) for 0x800_01fa.
    # 0x080001f8  [  11, 5] NS
    # 0x080001f8  [  70,16]
    # 0x080001fa  [  11, 5]
    # 0x08000202  [  12, 5] NS 
    #
    # These lines will return (11, 5) for 0x800_01fe. Row omitted.
    # 0x080001f8  [  11, 5] NS
    # 0x080001f8  [  70,16]
    # 0x080001fa  [  11, 5]
    # 0x08000202  [  12, 5] NS 
    for CU in dwarfinfo.iter_CUs():
        lineprog = dwarfinfo.line_program_for_CU(CU)
        prevstate = None
        for entry in lineprog.get_entries():
            # We're interested in those entries where a new state is assigned
            if entry.state is None:
                continue
            if entry.state.end_sequence:
                # if the line number sequence ends, clear prevstate.
                prevstate = None
                continue
            # Looking for a range of addresses in two consecutive states that
            # contain the required address.
            if prevstate and prevstate.address <= address < entry.state.address:
                filename = lineprog['file_entry'][prevstate.file - 1].name
                line = prevstate.line
                return filename, line
            prevstate = entry.state
    return None, None

def find_line(dwarfinfo , address):
    """ Return information about a line on the form:

        filename:line  content
    """
    filename, line = decode_file_line(dwarfinfo, address)
    if not filename:
        return ''
    filename = filename.decode('utf-8')
    path = os.path.join('example/debugging-optimized-code', filename)
    return '{:<30}{}'.format(filename + ':' + str(line), linecache.getline(path, line))

def find_function_range(dwarfinfo, name):
    """ Return the address span [lo, high) where the function NAME is defined."""
    for CU in dwarfinfo.iter_CUs():
        for DIE in CU.iter_DIEs():
            try:
                if DIE.tag == 'DW_TAG_subprogram':
                    if DIE.attributes['DW_AT_name'].value == name:
                        lowpc = DIE.attributes['DW_AT_low_pc'].value

                        # DWARF v4 in section 2.17 describes how to interpret the
                        # DW_AT_high_pc attribute based on the class of its form.
                        # For class 'address' it's taken as an absolute address
                        # (similarly to DW_AT_low_pc); for class 'constant', it's
                        # an offset from DW_AT_low_pc.
                        highpc_attr = DIE.attributes['DW_AT_high_pc']
                        highpc_attr_class = describe_form_class(highpc_attr.form)
                        if highpc_attr_class == 'address':
                            highpc = highpc_attr.value
                        elif highpc_attr_class == 'constant':
                            highpc = lowpc + highpc_attr.value
                        else:
                            print('Error: invalid DW_AT_high_pc class:',
                                highpc_attr_class)
                            continue
                        return lowpc, highpc
            except KeyError:
                continue
    return 0, 0

def disassemble(elf, name):
    """ Print source code intermixed with disassembly."""
    low_pc, high_pc = find_function_range(DWARF(elf), name)

    # TODO(dannas): Segment consists of multiple sections. We need to scan
    # sections to find which one contains our symbol.
    # Just assume for now that our symbol is in .text.
    section = elf.get_section_by_name('.text')
    low = low_pc - section['sh_addr']
    high = high_pc - section['sh_addr']
    data = section.data()[low:high]

    md = capstone.Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    prev = ''
    for i in md.disasm(data, low_pc):
        line = find_line(DWARF(elf), i.address)
        if line != prev and line:
            print(line, end='')
        prev = line
        print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))

elf = ELF('example/debugging-optimized-code/optimization-example.elf')
print_sizes(elf)
disassemble(elf, b'main')
