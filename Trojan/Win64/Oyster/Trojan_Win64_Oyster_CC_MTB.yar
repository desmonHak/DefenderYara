
rule Trojan_Win64_Oyster_CC_MTB{
	meta:
		description = "Trojan:Win64/Oyster.CC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 06 00 00 "
		
	strings :
		$a_03_0 = {45 33 c0 41 8b d5 48 8d 81 ?? ?? ?? ?? ff d0 } //3
		$a_01_1 = {b8 4d 5a 00 00 66 39 07 } //2
		$a_01_2 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //1 KERNEL32.DLL
		$a_01_3 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_4 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_5 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=9
 
}