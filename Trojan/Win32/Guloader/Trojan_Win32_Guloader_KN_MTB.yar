
rule Trojan_Win32_Guloader_KN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {64 65 6d 6f 64 75 6c 61 74 6f 72 65 6e 73 } //1 demodulatorens
		$a_81_1 = {66 6e 67 73 6c 69 6e 67 73 66 72 69 73 74 65 6e 20 65 6d 62 69 74 74 65 72 6d 65 6e 74 73 20 72 65 73 66 6c 65 6c 73 65 72 73 } //1 fngslingsfristen embitterments resflelsers
		$a_81_2 = {68 65 6d 6d 65 6c 69 67 68 65 64 73 66 75 6c 64 20 75 6e 69 64 65 6e 74 69 63 75 6c 61 74 65 20 65 74 68 79 6c 74 68 69 6f 65 74 68 61 6e 65 } //1 hemmelighedsfuld unidenticulate ethylthioethane
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}