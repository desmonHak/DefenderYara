
rule Trojan_Win32_Guloader_KO_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {64 61 6d 6e 64 65 73 74 20 72 6f 77 65 6e 61 } //1 damndest rowena
		$a_81_1 = {63 68 65 76 69 6f 74 20 6c 61 70 69 64 6f 73 65 } //1 cheviot lapidose
		$a_81_2 = {72 79 74 74 65 72 73 6b 65 2e 69 6e 69 } //1 rytterske.ini
		$a_81_3 = {73 6f 6c 6f 64 61 6e 73 65 72 69 6e 64 65 6e 73 2e 68 72 64 } //1 solodanserindens.hrd
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}