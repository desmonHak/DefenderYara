
rule Trojan_Win32_Guloader_GPR_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {6d 65 6e 69 6e 67 73 6d 61 61 6c 69 6e 67 65 6e 20 6c 69 71 75 65 75 72 73 2e 65 78 65 } //1 meningsmaalingen liqueurs.exe
		$a_81_1 = {73 74 69 6c 65 68 66 74 65 72 6e 65 20 6b 6f 6b 65 74 74 65 72 65 64 65 73 } //1 stilehfterne koketteredes
		$a_81_2 = {70 6f 6d 70 6f 6d } //1 pompom
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}