
rule Trojan_Win32_Guloader_KL_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {6b 69 73 73 65 6d 69 73 73 65 } //1 kissemisse
		$a_81_1 = {65 72 73 68 20 73 6b 69 76 } //1 ersh skiv
		$a_81_2 = {73 65 6e 67 65 6b 6c 64 65 72 2e 65 78 65 } //1 sengeklder.exe
		$a_81_3 = {70 61 6e 73 72 69 6e 67 65 72 73 20 69 72 72 69 74 65 72 65 74 } //1 pansringers irriteret
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}