
rule Trojan_Win64_ShellcodeLoader_IUY_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeLoader.IUY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {36 32 2e 36 30 2e 32 32 36 2e 32 34 38 3a 35 35 35 33 2f 6d 61 79 2e 62 69 6e } //1 62.60.226.248:5553/may.bin
		$a_01_1 = {76 69 76 6f 6c 74 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 76 69 76 6f 6c 74 2e 70 64 62 } //1 vivolt\x64\Release\vivolt.pdb
		$a_01_2 = {5c 4f 6e 65 44 72 69 76 65 } //1 \OneDrive
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}