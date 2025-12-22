
rule Trojan_Win32_Guloader_GPX_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {75 64 72 69 6e 67 6e 69 6e 67 65 72 73 20 62 72 75 67 73 72 69 67 74 69 67 65 72 65 20 73 74 6e 69 6e 67 73 73 74 72 65 6e 67 65 6e } //1 udringningers brugsrigtigere stningsstrengen
		$a_81_1 = {67 65 6e 66 6f 72 74 6f 6c 6b 65 73 20 73 6f 6c 73 6b 72 6d 65 6e 20 61 72 61 77 61 } //1 genfortolkes solskrmen arawa
		$a_81_2 = {66 75 6d 69 66 65 72 6f 75 73 2e 68 74 6d } //1 fumiferous.htm
		$a_81_3 = {70 61 6c 69 73 61 6e 64 65 72 65 74 73 2e 7a 69 70 } //1 palisanderets.zip
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}