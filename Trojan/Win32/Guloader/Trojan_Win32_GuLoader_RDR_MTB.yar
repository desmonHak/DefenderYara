
rule Trojan_Win32_GuLoader_RDR_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RDR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {75 76 61 6e 6c 69 67 65 72 65 6f 6d 6b } //1 uvanligereomk
		$a_81_1 = {4e 4f 4e 53 54 49 43 } //1 NONSTIC
		$a_81_2 = {4d 65 6f 75 73 67 61 76 65 62 6f } //1 Meousgavebo
		$a_81_3 = {75 6e 61 77 61 72 65 6c 79 6d 65 64 } //1 unawarelymed
		$a_81_4 = {49 4e 53 54 52 55 4b 54 49 4f 4e 53 } //1 INSTRUKTIONS
		$a_81_5 = {41 6e 74 69 36 30 } //1 Anti60
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}