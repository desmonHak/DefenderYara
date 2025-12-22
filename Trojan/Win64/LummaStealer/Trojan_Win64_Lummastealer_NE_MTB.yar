
rule Trojan_Win64_Lummastealer_NE_MTB{
	meta:
		description = "Trojan:Win64/Lummastealer.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8d 54 24 68 48 89 14 24 48 89 c3 31 c9 48 89 cf 31 f6 41 b8 04 00 00 00 45 31 c9 4d 89 ca 4c 8d 9c 24 a0 00 00 00 4c 89 c8 } //2
		$a_01_1 = {48 85 c0 74 1e 0f b6 54 24 49 84 d2 74 0b 48 8b 5c 24 60 48 89 58 30 eb 0f } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}