
rule Trojan_Win32_Guloader_GQG_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6f 76 65 72 70 72 73 69 64 69 65 74 73 2e 74 69 6e } //1 overprsidiets.tin
		$a_81_1 = {61 64 64 65 72 69 6e 67 65 72 6e 65 5c 75 6e 73 69 74 75 61 74 65 64 2e 67 69 66 } //1 adderingerne\unsituated.gif
		$a_81_2 = {62 6f 6e 6b 61 6d 6d 65 72 61 74 65 72 73 2e 66 6c 69 } //1 bonkammeraters.fli
		$a_81_3 = {61 76 6c 73 61 72 62 65 6a 64 65 73 5c 74 79 72 6b 69 65 74 2e 7a 69 70 } //1 avlsarbejdes\tyrkiet.zip
		$a_81_4 = {6b 6f 6c 6f 72 69 74 74 65 72 5c 4d 6f 6e 6f 73 70 6f 72 65 64 5c 76 69 64 73 6b 72 6d 74 2e 69 6e 69 } //1 koloritter\Monospored\vidskrmt.ini
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}