
rule Trojan_Win32_Guloader_GQC_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GQC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {74 65 6c 65 6d 65 74 72 65 6e 65 20 61 70 6f 6d 69 78 65 73 20 69 6f 74 69 7a 69 6e 67 } //1 telemetrene apomixes iotizing
		$a_81_1 = {70 73 79 63 68 6f 74 68 65 69 73 74 } //1 psychotheist
		$a_81_2 = {63 6c 65 76 65 72 65 73 74 2e 65 78 65 } //1 cleverest.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}