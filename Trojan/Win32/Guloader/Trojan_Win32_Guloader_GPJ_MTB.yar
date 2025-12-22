
rule Trojan_Win32_Guloader_GPJ_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GPJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {65 75 72 6f 61 66 73 74 65 6d 6e 69 6e 67 20 74 65 6d 70 65 72 65 72 65 } //1 euroafstemning temperere
		$a_81_1 = {69 6d 70 72 65 73 74 69 6e 67 20 75 6e 69 74 61 72 69 6e 65 73 73 2e 65 78 65 } //1 impresting unitariness.exe
		$a_81_2 = {64 69 67 65 73 74 69 76 65 20 70 61 70 65 72 6d 61 6b 65 72 } //1 digestive papermaker
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}