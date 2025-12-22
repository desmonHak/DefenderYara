
rule Trojan_Win64_ShellcodeRunner_AMS_MTB{
	meta:
		description = "Trojan:Win64/ShellcodeRunner.AMS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_80_0 = {34 36 2e 31 34 39 2e 37 31 2e 32 33 30 } //46.149.71.230  4
		$a_80_1 = {25 73 64 6f 63 75 6d 65 6e 74 5f 25 30 34 64 25 30 32 64 25 30 32 64 5f 25 30 32 64 25 30 32 64 25 30 32 64 2e 70 64 66 } //%sdocument_%04d%02d%02d_%02d%02d%02d.pdf  1
		$a_80_2 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //OpenProcess  1
		$a_80_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 } //VirtualAllocEx  1
		$a_80_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //VirtualProtect  1
		$a_80_5 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //WriteProcessMemory  1
		$a_80_6 = {43 72 65 61 74 65 52 65 6d 6f 74 65 54 68 72 65 61 64 } //CreateRemoteThread  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=10
 
}