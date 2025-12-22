
rule Trojan_Win64_MuddyWater_DA_MTB{
	meta:
		description = "Trojan:Win64/MuddyWater.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8b 04 24 b9 20 00 00 00 48 f7 f1 48 8b c2 48 8b 4c 24 30 0f b6 04 01 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 0f b6 09 33 c8 8b c1 48 8b 0c 24 48 8b 54 24 20 48 03 d1 48 8b ca 88 01 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}