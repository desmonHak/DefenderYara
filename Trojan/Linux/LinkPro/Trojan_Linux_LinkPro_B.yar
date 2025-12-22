
rule Trojan_Linux_LinkPro_B{
	meta:
		description = "Trojan:Linux/LinkPro.B,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {67 65 74 64 65 6e 74 73 } //1 getdents
		$a_00_1 = {72 65 61 64 64 69 72 } //1 readdir
		$a_00_2 = {2e 74 6d 70 7e 64 61 74 61 } //1 .tmp~data
		$a_00_3 = {2f 70 72 6f 63 2f 6e 65 74 } //1 /proc/net
		$a_00_4 = {2e 73 79 73 74 65 6d } //1 .system
		$a_00_5 = {73 73 68 69 64 73 } //1 sshids
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}