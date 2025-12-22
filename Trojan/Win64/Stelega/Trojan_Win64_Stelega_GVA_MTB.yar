
rule Trojan_Win64_Stelega_GVA_MTB{
	meta:
		description = "Trojan:Win64/Stelega.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 8b c1 4a 8d 54 02 10 0f b6 12 33 c2 89 45 d4 8b 45 bc ff c0 89 45 bc 8b 45 bc 3b 45 d8 0f 9c c0 0f b6 c0 89 45 b8 83 7d b8 00 75 b4 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}