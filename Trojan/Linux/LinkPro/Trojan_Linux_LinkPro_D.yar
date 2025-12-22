
rule Trojan_Linux_LinkPro_D{
	meta:
		description = "Trojan:Linux/LinkPro.D,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 73 79 73 63 61 6c 6c 73 2f 73 79 73 5f 65 6e 74 65 72 5f 67 65 74 64 65 6e 74 73 } //1 /syscalls/sys_enter_getdents
		$a_00_1 = {2f 73 79 73 63 61 6c 6c 73 2f 73 79 73 5f 65 78 69 74 5f 67 65 74 64 65 6e 74 73 } //1 /syscalls/sys_exit_getdents
		$a_00_2 = {2f 73 79 73 63 61 6c 6c 73 2f 73 79 73 5f 65 6e 74 65 72 5f 62 70 66 } //1 /syscalls/sys_enter_bpf
		$a_00_3 = {42 50 46 20 63 6d 64 3a 20 25 64 2c 20 73 74 61 72 74 5f 69 64 3a 20 25 75 } //1 BPF cmd: %d, start_id: %u
		$a_00_4 = {48 49 44 49 4e 47 20 4e 45 58 54 5f 49 44 3a 20 25 75 } //1 HIDING NEXT_ID: %u
		$a_00_5 = {2e 74 6d 70 7e 64 61 74 61 } //1 .tmp~data
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}