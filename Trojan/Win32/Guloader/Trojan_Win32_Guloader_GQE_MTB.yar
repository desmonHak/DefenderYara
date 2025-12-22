
rule Trojan_Win32_Guloader_GQE_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {62 75 6b 73 65 74 72 6f 6c 64 65 73 20 79 74 72 69 6e 67 } //1 buksetroldes ytring
		$a_81_1 = {66 6f 72 65 6e 65 6e 64 65 } //1 forenende
		$a_81_2 = {61 72 63 68 64 61 70 69 66 65 72 73 68 69 70 2e 65 78 65 } //1 archdapifership.exe
		$a_81_3 = {67 65 6e 6e 65 6d 6c 65 76 65 20 69 6e 74 65 72 6e 65 72 65 73 20 6f 6d 64 65 66 69 6e 65 72 65 74 } //1 gennemleve interneres omdefineret
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}