
rule Trojan_Win32_Guloader_KF_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {65 76 65 6e 74 79 72 6c 79 73 74 5c 62 79 73 74 61 74 73 } //1 eventyrlyst\bystats
		$a_81_1 = {41 6e 65 73 74 72 69 2e 72 69 62 } //1 Anestri.rib
		$a_81_2 = {64 69 61 6c 6c 61 67 65 73 2e 72 6e 65 } //1 diallages.rne
		$a_81_3 = {66 75 73 74 69 6e 65 6c 6c 61 2e 69 6d 70 } //1 fustinella.imp
		$a_81_4 = {70 65 72 69 67 6f 6e 65 2e 75 64 74 } //1 perigone.udt
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}