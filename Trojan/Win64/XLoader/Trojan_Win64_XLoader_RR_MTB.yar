
rule Trojan_Win64_XLoader_RR_MTB{
	meta:
		description = "Trojan:Win64/XLoader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 c6 04 11 ff 48 c1 e9 0a 48 03 0d f0 b0 18 00 80 39 ff } //1
		$a_01_1 = {4c 63 d2 46 0f b6 0c 11 46 88 0c 10 ff c2 4c 63 d2 4d 3b d0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}