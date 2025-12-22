
rule Trojan_Win32_Guloader_GPP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {66 6c 69 70 70 65 6e 64 65 73 } //1 flippendes
		$a_81_1 = {73 61 64 64 65 6c 6d 61 67 65 72 61 72 62 65 6a 64 65 72 6e 65 73 } //1 saddelmagerarbejdernes
		$a_81_2 = {61 66 66 61 6c 64 73 62 6f 72 74 73 6b 61 66 66 65 6c 73 65 73 6f 6d 72 61 61 64 65 72 6e 65 20 73 70 72 6e 67 62 6f 6d 62 65 72 6e 65 } //1 affaldsbortskaffelsesomraaderne sprngbomberne
		$a_81_3 = {61 75 73 70 69 63 61 74 65 2e 65 78 65 } //1 auspicate.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}