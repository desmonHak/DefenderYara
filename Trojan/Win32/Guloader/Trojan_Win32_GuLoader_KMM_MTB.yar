
rule Trojan_Win32_GuLoader_KMM_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.KMM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 05 00 06 00 00 "
		
	strings :
		$a_81_0 = {52 61 63 68 69 6f 6d 79 65 6c 69 74 69 73 } //1 Rachiomyelitis
		$a_81_1 = {64 61 67 73 72 75 74 69 6e 65 72 6e 65 73 } //1 dagsrutinernes
		$a_81_2 = {63 6f 6e 67 65 6e 65 72 69 63 61 6c } //1 congenerical
		$a_81_3 = {5c 52 65 73 6e 69 63 6b 2e 6a 70 67 } //1 \Resnick.jpg
		$a_81_4 = {75 6e 70 61 72 61 64 6f 78 69 63 61 6c 6c 79 } //1 unparadoxically
		$a_81_5 = {48 61 62 73 62 75 72 67 65 72 65 6e } //1 Habsburgeren
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=5
 
}