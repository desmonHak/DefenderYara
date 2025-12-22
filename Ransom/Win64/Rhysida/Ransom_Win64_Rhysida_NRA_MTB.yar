
rule Ransom_Win64_Rhysida_NRA_MTB{
	meta:
		description = "Ransom:Win64/Rhysida.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_81_0 = {52 68 79 73 69 64 61 2d 30 2e 33 } //2 Rhysida-0.3
		$a_81_1 = {47 65 74 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 49 6e 66 6f } //1 GetProcessMemoryInfo
		$a_81_2 = {45 6e 75 6d 50 72 6f 63 65 73 73 65 73 } //1 EnumProcesses
		$a_81_3 = {41 45 53 20 45 6e 63 72 79 70 74 } //1 AES Encrypt
		$a_01_4 = {48 0f bd c2 48 83 f0 3f 85 c0 89 c3 } //2
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_01_4  & 1)*2) >=7
 
}