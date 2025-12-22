
rule Trojan_Win64_UACBypass_HS_MTB{
	meta:
		description = "Trojan:Win64/UACBypass.HS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {5c 52 65 6c 65 61 73 65 5c 42 79 70 61 73 73 55 41 43 2e 70 64 62 } //1 \Release\BypassUAC.pdb
		$a_00_1 = {63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 c:\users\public\test.exe
		$a_00_2 = {5c 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //1 \explorer.exe
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}