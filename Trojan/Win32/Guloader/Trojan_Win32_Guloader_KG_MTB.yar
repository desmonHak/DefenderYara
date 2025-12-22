
rule Trojan_Win32_Guloader_KG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6d 69 6d 6f 73 65 73 20 66 69 6c 6d 65 6e 2e 65 78 65 } //1 mimoses filmen.exe
		$a_81_1 = {67 69 62 62 65 72 6e 61 6b 6b 65 72 6e 65 73 } //1 gibbernakkernes
		$a_81_2 = {62 69 6c 66 72 61 67 74 65 72 6e 65 73 2e 7a 69 70 } //1 bilfragternes.zip
		$a_81_3 = {68 79 70 65 72 73 74 72 6f 70 68 69 63 5c 6d 69 6e 69 6d 61 2e 7a 69 70 } //1 hyperstrophic\minima.zip
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}