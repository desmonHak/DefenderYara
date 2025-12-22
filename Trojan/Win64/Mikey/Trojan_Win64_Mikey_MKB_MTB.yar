
rule Trojan_Win64_Mikey_MKB_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 0f b6 0b 4c 8d 05 2d 93 01 00 ba 03 00 00 00 48 8b cf ?? ?? ?? ?? ?? 48 83 c7 04 48 8d 5b 01 48 83 ee 01 } //15
		$a_03_1 = {48 85 c0 c7 44 24 28 ?? 00 00 00 4c 8d 8d ?? ?? 00 00 48 89 7c 24 ?? 4c 0f 44 cf 4c 8d 44 24 ?? 33 c9 48 8d 15 8a 88 01 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}