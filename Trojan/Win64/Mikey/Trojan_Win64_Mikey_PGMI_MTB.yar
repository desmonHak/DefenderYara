
rule Trojan_Win64_Mikey_PGMI_MTB{
	meta:
		description = "Trojan:Win64/Mikey.PGMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {42 0f 10 04 06 42 0f 10 4c 06 10 42 0f 10 14 00 0f 57 d0 42 0f 10 44 00 10 0f 57 c1 42 0f 11 14 07 42 0f 11 44 07 10 49 83 c0 ?? 4c 39 c2 75 d0 } //5
		$a_03_1 = {46 8b 0c 00 46 33 0c 06 46 89 0c 07 49 83 c0 ?? 4c 39 c2 75 eb } //5
		$a_01_2 = {46 0f b6 14 00 46 32 14 06 46 88 14 07 49 ff c0 49 ff c9 75 eb } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}