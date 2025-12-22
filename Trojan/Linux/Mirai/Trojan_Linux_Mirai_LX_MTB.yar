
rule Trojan_Linux_Mirai_LX_MTB{
	meta:
		description = "Trojan:Linux/Mirai.LX!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {4b 69 6c 6c 20 62 79 70 61 73 73 20 61 74 74 65 6d 70 74 } //2 Kill bypass attempt
		$a_01_1 = {4b 69 6c 6c 20 62 6c 61 63 6b 6c 69 73 74 } //1 Kill blacklist
		$a_01_2 = {4d 69 73 73 69 6e 67 20 66 64 73 } //1 Missing fds
		$a_01_3 = {4b 69 6c 6c 20 6e 65 77 } //1 Kill new
		$a_01_4 = {44 65 6c 65 74 65 64 } //1 Deleted
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}