
rule Trojan_Win64_Sdum_CF_MTB{
	meta:
		description = "Trojan:Win64/Sdum.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 50 45 58 5f 54 4d 48 5f 4c 4f 41 44 45 52 2e 70 64 62 } //2 APEX_TMH_LOADER.pdb
		$a_01_1 = {2e 6d 61 6e 61 67 65 64 63 6f 64 65 } //2 .managedcode
		$a_01_2 = {68 79 64 72 61 74 65 64 } //2 hydrated
		$a_01_3 = {50 45 58 5f 54 4d 48 5f 4c 4f 41 44 45 52 2e 65 78 65 } //2 PEX_TMH_LOADER.exe
		$a_01_4 = {44 00 4f 00 54 00 4e 00 45 00 54 00 5f 00 } //2 DOTNET_
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=10
 
}