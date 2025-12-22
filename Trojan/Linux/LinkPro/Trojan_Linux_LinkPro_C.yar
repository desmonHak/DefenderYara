
rule Trojan_Linux_LinkPro_C{
	meta:
		description = "Trojan:Linux/LinkPro.C,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_00_0 = {68 6f 6f 6b 5f 75 64 70 36 5f 73 65 71 5f 73 68 6f 77 } //1 hook_udp6_seq_show
		$a_00_1 = {68 6f 6f 6b 5f 75 64 70 34 5f 73 65 71 5f 73 68 6f 77 } //1 hook_udp4_seq_show
		$a_00_2 = {68 6f 6f 6b 5f 74 63 70 36 5f 73 65 71 5f 73 68 6f 77 } //1 hook_tcp6_seq_show
		$a_00_3 = {68 6f 6f 6b 5f 74 63 70 34 5f 73 65 71 5f 73 68 6f 77 } //1 hook_tcp4_seq_show
		$a_00_4 = {66 74 72 61 63 65 5f 74 68 75 6e 6b } //1 ftrace_thunk
		$a_00_5 = {68 69 64 65 5f 70 6f 72 74 5f 69 6e 69 74 } //1 hide_port_init
		$a_00_6 = {68 69 64 65 5f 70 6f 72 74 5f 65 78 69 74 } //1 hide_port_exit
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=6
 
}