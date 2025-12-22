
rule Trojan_Win64_Oyster_CD_MTB{
	meta:
		description = "Trojan:Win64/Oyster.CD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_03_0 = {48 8b c8 ff 15 ?? ?? ?? ?? 48 8b 05 ?? ?? ?? ?? 48 05 ?? ?? ?? ?? ff d0 45 33 c9 45 33 c0 33 d2 33 c9 } //2
		$a_01_1 = {4b 00 45 00 52 00 4e 00 45 00 4c 00 33 00 32 00 2e 00 44 00 4c 00 4c } //1
		$a_01_2 = {4c 6f 61 64 4c 69 62 72 61 72 79 41 } //1 LoadLibraryA
		$a_01_3 = {47 65 74 50 72 6f 63 41 64 64 72 65 73 73 } //1 GetProcAddress
		$a_01_4 = {56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 } //1 VirtualProtect
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}