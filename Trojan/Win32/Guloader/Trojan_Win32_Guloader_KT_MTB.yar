
rule Trojan_Win32_Guloader_KT_MTB{
	meta:
		description = "Trojan:Win32/Guloader.KT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {73 74 69 74 72 65 72 } //1 stitrer
		$a_81_1 = {6b 75 67 6c 65 73 74 64 73 20 73 69 65 67 69 6e 67 } //1 kuglestds sieging
		$a_81_2 = {6b 65 67 6c 65 72 65 6a 73 65 72 6e 65 73 20 73 74 75 64 69 65 72 65 6a 73 65 73 2e 65 78 65 } //1 keglerejsernes studierejses.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}