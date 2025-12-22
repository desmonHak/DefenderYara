
rule Trojan_Win32_Guloader_UBC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.UBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_81_0 = {54 65 74 72 61 63 65 72 6f 75 73 39 38 2e 68 61 76 } //1 Tetracerous98.hav
		$a_81_1 = {65 78 6f 70 68 74 68 61 6c 6d 69 63 2e 75 64 73 } //1 exophthalmic.uds
		$a_81_2 = {6c 69 74 75 72 67 79 2e 73 6e 69 } //1 liturgy.sni
		$a_81_3 = {72 65 6e 64 65 72 65 72 73 2e 64 69 70 } //1 renderers.dip
		$a_81_4 = {75 6e 62 65 6e 75 6d 62 } //1 unbenumb
		$a_81_5 = {5c 54 68 61 6e 6a 61 73 5c 75 6b 72 61 69 6e 65 72 2e 69 6e 69 } //1 \Thanjas\ukrainer.ini
		$a_81_6 = {70 73 79 63 68 6f 61 6e 61 6c 79 73 74 5c 64 72 61 70 65 72 69 5c 69 6c 64 73 70 61 61 73 74 74 65 6c 73 65 72 } //1 psychoanalyst\draperi\ildspaasttelser
		$a_81_7 = {5c 66 61 74 61 6d 6f 72 67 61 6e 61 65 74 73 5c 67 61 6d 6c 69 6e 67 65 } //1 \fatamorganaets\gamlinge
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1) >=8
 
}