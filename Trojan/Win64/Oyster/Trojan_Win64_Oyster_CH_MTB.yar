
rule Trojan_Win64_Oyster_CH_MTB{
	meta:
		description = "Trojan:Win64/Oyster.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 83 ec 28 48 8b 0d ?? ?? ?? ?? 45 33 c0 ba 01 00 00 00 48 8d 81 ?? ?? ?? ?? ff d0 48 8b 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? 48 83 c4 28 48 ff e0 } //2
		$a_01_1 = {4b 45 52 4e 45 4c 33 32 2e 44 4c 4c } //1 KERNEL32.DLL
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}