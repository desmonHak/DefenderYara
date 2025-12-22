
rule Trojan_Win32_Amadey_MTH_MTB{
	meta:
		description = "Trojan:Win32/Amadey.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {32 7a 31 36 39 30 2e 65 78 65 } //1 2z1690.exe
		$a_81_1 = {31 64 35 35 65 39 2e 65 78 65 } //1 1d55e9.exe
		$a_81_2 = {68 61 74 65 72 2f 6e 69 72 63 6d 64 2e 65 78 65 } //1 hater/nircmd.exe
		$a_81_3 = {49 6e 73 74 61 6c 6c 48 69 6e 66 53 65 63 74 69 6f 6e 20 25 73 20 31 32 38 } //1 InstallHinfSection %s 128
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}