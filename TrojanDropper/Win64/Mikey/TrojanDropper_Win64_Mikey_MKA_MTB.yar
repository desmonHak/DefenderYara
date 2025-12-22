
rule TrojanDropper_Win64_Mikey_MKA_MTB{
	meta:
		description = "TrojanDropper:Win64/Mikey.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 44 ?? 33 c1 48 63 0c 24 66 89 44 4c ?? 48 63 04 24 } //15
		$a_01_1 = {c6 84 24 9a 00 00 00 4b c6 84 24 9b 00 00 00 00 c6 84 24 9c 00 00 00 48 c6 84 24 9d 00 00 00 00 c6 84 24 9e 00 00 00 2c } //10
	condition:
		((#a_03_0  & 1)*15+(#a_01_1  & 1)*10) >=25
 
}