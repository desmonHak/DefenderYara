
rule Trojan_Linux_LinkPro_A{
	meta:
		description = "Trojan:Linux/LinkPro.A,SIGNATURE_TYPE_ELFHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {6c 69 6e 6b 2d 70 72 6f 2f 6c 69 6e 6b 2d 63 6c 69 65 6e 74 } //1 link-pro/link-client
		$a_00_1 = {72 65 73 6f 75 72 63 65 73 2f 6c 69 62 6c 64 2e 73 6f } //1 resources/libld.so
		$a_00_2 = {72 65 73 6f 75 72 63 65 73 2f 61 72 70 5f 64 69 61 67 2e 6b 6f } //1 resources/arp_diag.ko
		$a_00_3 = {68 69 64 65 50 72 6f 67 72 61 6d 73 } //1 hidePrograms
		$a_00_4 = {6b 6e 6f 63 6b 5f 70 72 6f 67 } //1 knock_prog
		$a_00_5 = {63 72 65 61 63 6b 2f 70 74 79 } //1 creack/pty
		$a_00_6 = {72 65 73 6f 63 6b 73 } //1 resocks
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}