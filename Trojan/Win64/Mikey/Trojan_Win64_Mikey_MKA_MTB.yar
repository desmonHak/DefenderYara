
rule Trojan_Win64_Mikey_MKA_MTB{
	meta:
		description = "Trojan:Win64/Mikey.MKA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b6 c0 41 8b c8 2b c8 8b c1 49 8d 49 01 99 33 c2 2b c2 3c 01 41 0f b6 c0 49 0f 45 c9 } //15
		$a_03_1 = {0f b6 44 33 01 0f b6 0c 33 2b c1 99 33 c2 2b c2 3c 01 ?? ?? 48 8b 07 89 5c 87 08 48 ff 07 } //10
	condition:
		((#a_01_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}