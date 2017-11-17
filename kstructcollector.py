import os
import sys
import argparse
import re
import subprocess

KMALLOC_CACHES = [96, 128, 192, 256, 512, 1024, 2048, 4096, 8192]

class KStruct:
    """Kernel struct 
    """

    def __init__(self, ks_class, ks_size, ks_lines):
        self.ks_class = ks_class
        self.ks_size = ks_size
        self.ks_lines = ks_lines

    def set_class(self, ks_class):
        self.ks_class = ks_class
    def get_class(self):
        return self.ks_class

    def set_size(self, ks_size):
        self.ks_size = ks_size
    def get_size(self):
        return self.ks_size
    
    def set_lines(self, ks_lines):
        self.ks_lines = ks_lines
    def get_lines(self):
        return '\n'.join(self.ks_lines)

    def __str__(self):
        return 'KStruct - class: %s, size: %s' % (self.ks_class, self.ks_size, )

def exec_cmd(cmd):
    """Execute command into shell

    Args: 
        cmd (list): Command to be executed

    Returns:
        (int, string, string): Command return code, stdout and stderr 
    """
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    return (p.returncode, stdout, stderr)

def check_requirements(elf):
    """Check system requirements

    Args: 
        elf (string): elf filepath

    Returns:
        int: 0 if successful, !=0 otherwise
    """
    cmd = ['pahole', '--version']
    ret, stdout, stderr = exec_cmd(cmd)
    if ret != 0:
        print '[-] Unable to find: pahole'
        return 1
    if not os.path.exists(elf):
        print '[-] Unable to locate: %s' % (elf, )
        return 1
    return 0

def get_kmalloc_cache(size):
    """Get the corresponding kmalloc cache according the size

    Args: 
        size (int): Size

    Returns: 
        int: kmalloc cache size
    """
    for s in KMALLOC_CACHES:
        if s > size:
            return s
    raise ValueError('Unable to find corresponding kmalloc cache')

def collect_struct_info(lines):
    """Collect struct informations: size and class name

    Args: 
        lines (list): List of all the struct parsed lines

    Returns: 
        int, string: Size and class name
    """
    p_size  = re.compile('.*size:[\W]*(\d*).*')
    p_class = re.compile('struct[\W]*(\w*).*')
    s_size  = 0
    s_class = None
    for line in lines:
        m_size = p_size.match(line)
        if m_size:
            s_size = m_size.group(1)
        m_class = p_class.match(line)
        if m_class:
            s_class = m_class.group(1)
    return int(s_size), s_class

def init_kstructs_dict(s_size):
    """Init kernel structs dictionary

    Args: 
        s_size (int/None): Selected size

    Returns: 
        dict: kernel structs, divided by kmalloc caches size
    """
    kstructs = {}
    if s_size: 
        kstructs[s_size] = []
    else:
        for c in KMALLOC_CACHES:
            kstructs[c] = []
    return kstructs

def collect_kstructs(elf, s_size):
    """Collect kernel structs 

    Args: 
        elf (string): Kernel elf filepath
        s_size (int/None): Selected size

    Returns: 
        dict: kernel structs, divided by kmalloc caches size
    """
    kstructs = init_kstructs_dict(s_size)
    cmd = ['pahole', elf]
    ret, stdout, stderr = exec_cmd(cmd)
    if ret != 0:
        print '[-] Something wrong during execution of: %s' % (' '.join(cmd), )
        return None

    ks_lines = []
    for line in stdout.split('\n'):
        ks_lines.append(line)
        if line == '};':
            ks_size, ks_class = collect_struct_info(ks_lines)
            try: 
                kc_size = get_kmalloc_cache(ks_size)
            except ValueError:
                ks_lines = []
                continue

            if kc_size in kstructs.keys():
                kstructs[kc_size].append(KStruct(ks_class, ks_size, ks_lines))
            ks_lines = []
    return kstructs

def dump_kstructs(kstructs, output):
    """Dump kernel structs

    Args:
        kstructs (dict): Kernel struct dictionary
        output (string/None): Output file
    """
    lines = []
    for size in kstructs:
        lines.append('Kernel structs allocated in kmalloc cache %s:\n\n' % (size, ))
        for kstruct in kstructs[size]:
            lines.append('%s\n\n' % (kstruct.get_lines(), ))
    
    if output:
        with open(output, 'w') as f:
            f.writelines(lines)
    else:
        print '\n'.join(lines)


def main(elf, req_size, output):
    """Main routine

    Args:
        elf (string): Linux kernel ELF filepath
        req_size (int/None): Requested size
        output (string/None): Output file

    Returns:
        int: 0 if successful, !=0 otherwise
    """
    print '[+] Check requirements'
    if check_requirements(elf) != 0:
        return 1
    print '[+] Collect kernel structs'
    kstructs = collect_kstructs(elf, req_size)
    print '[+] Dump kernel structs'
    dump_kstructs(kstructs, output)
    return 0

"""Run as script
"""
if __name__ == '__main__':
    # Set arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('elf', action='store', help='Linux kernel ELF file')
    parser.add_argument('-s', '--size', action='store', type=int, 
        help='Filter for kmalloc caches size. Available sizes: %s' % (' '.join(map(str, KMALLOC_CACHES)), ))
    parser.add_argument('-o', '--output', action='store', 
        help='Dump results to file')

    args = parser.parse_args()

    # Run
    sys.exit(main(args.elf, args.size, args.output))

