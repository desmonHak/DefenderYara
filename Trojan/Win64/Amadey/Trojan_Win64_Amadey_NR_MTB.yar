
rule Trojan_Win64_Amadey_NR_MTB{
	meta:
		description = "Trojan:Win64/Amadey.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 89 d1 48 f7 ea 48 d1 fa 4c 8d 14 52 4a 8d 14 52 4c 89 c8 49 29 d1 49 83 f9 02 0f 8f b9 02 00 00 } //2
		$a_01_1 = {48 29 ca 88 50 01 bb 02 00 00 00 48 89 d9 0f 1f 44 00 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}