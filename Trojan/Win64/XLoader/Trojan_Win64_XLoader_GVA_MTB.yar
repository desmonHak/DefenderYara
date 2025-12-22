
rule Trojan_Win64_XLoader_GVA_MTB{
	meta:
		description = "Trojan:Win64/XLoader.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d1 48 8d 44 10 10 0f b6 00 48 8b 4d c0 30 01 8b 45 d8 ff c0 89 45 d8 8b 45 d8 3b 45 dc 0f 9c c0 0f b6 c0 89 45 d4 83 7d d4 00 75 a3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}