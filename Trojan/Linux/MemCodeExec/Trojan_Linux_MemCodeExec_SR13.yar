
rule Trojan_Linux_MemCodeExec_SR13{
	meta:
		description = "Trojan:Linux/MemCodeExec.SR13,SIGNATURE_TYPE_ELFHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_80_0 = {5b 64 61 74 61 7c 62 73 73 7c 73 74 61 63 6b 7c 73 74 61 63 6b 2d 65 78 65 63 7c 6d 61 6c 6c 6f 63 2d 72 77 7c 6d 61 6c 6c 6f 63 2d 72 77 2d 78 7c 6d 6d 61 70 2d 72 77 7c 6d 6d 61 70 2d 72 77 78 7c } //[data|bss|stack|stack-exec|malloc-rw|malloc-rw-x|mmap-rw|mmap-rwx|  1
		$a_80_1 = {7c 6d 6d 61 70 2d 72 77 2d 78 7c 73 68 6d 2d 6f 70 65 6e 2d 72 77 78 7c 73 68 6d 67 65 74 2d 72 77 7c 73 68 6d 67 65 74 2d 72 77 78 7c 73 68 6d 67 65 74 2d 72 77 2d 78 5d } //|mmap-rw-x|shm-open-rwx|shmget-rw|shmget-rwx|shmget-rw-x]  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}