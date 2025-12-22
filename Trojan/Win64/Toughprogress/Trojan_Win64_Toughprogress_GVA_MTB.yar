
rule Trojan_Win64_Toughprogress_GVA_MTB{
	meta:
		description = "Trojan:Win64/Toughprogress.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {42 0f b7 44 4d 00 42 8b 0c 8e 49 03 ca 44 8b 04 87 b8 0f 17 00 00 4d 03 c2 0f be 11 85 d2 74 10 6b c0 21 48 8d 49 01 03 c2 0f be 11 85 d2 75 f0 3b c3 74 1f 49 ff c1 4d 3b cb 72 c4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}