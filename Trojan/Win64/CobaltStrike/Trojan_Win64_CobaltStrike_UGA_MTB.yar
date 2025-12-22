
rule Trojan_Win64_CobaltStrike_UGA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.UGA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 d2 44 29 ca 41 89 d2 48 63 d2 44 0f b6 0c 14 46 88 0c 1c 88 0c 14 42 02 0c 1c 0f b6 c9 0f b6 14 0c 42 32 14 06 42 88 14 03 49 83 c0 ?? 4c 39 c7 75 a3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}