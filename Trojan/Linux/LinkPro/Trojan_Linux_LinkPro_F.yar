
rule Trojan_Linux_LinkPro_F{
	meta:
		description = "Trojan:Linux/LinkPro.F,SIGNATURE_TYPE_ELFHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2f 74 6d 70 2f 2e 64 65 6c } //1 /tmp/.del
		$a_00_1 = {65 78 70 61 6e 64 20 33 32 2d 62 79 74 65 20 6b } //1 expand 32-byte k
		$a_00_2 = {63 6f 73 6d 61 6e 6b 69 6e 67 } //1 cosmanking
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}