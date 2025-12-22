
rule Trojan_Win32_Guloader_GQH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6e 6f 73 65 62 6f 6e 65 20 61 70 61 72 74 68 65 69 64 } //1 nosebone apartheid
		$a_81_1 = {69 6e 64 65 68 6f 6c 64 65 6e 64 65 73 20 65 70 69 74 6f 6d 61 74 6f 72 79 } //1 indeholdendes epitomatory
		$a_81_2 = {73 70 65 63 69 61 6c 74 61 73 74 65 72 6e 65 20 6e 6f 6e 75 74 69 6c 69 74 79 2e 65 78 65 } //1 specialtasterne nonutility.exe
		$a_81_3 = {68 64 65 72 73 67 61 76 65 72 73 } //1 hdersgavers
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}