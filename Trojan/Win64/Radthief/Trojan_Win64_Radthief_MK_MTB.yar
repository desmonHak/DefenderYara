
rule Trojan_Win64_Radthief_MK_MTB{
	meta:
		description = "Trojan:Win64/Radthief.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {45 0f b6 23 45 84 e4 ?? ?? 4c 8d 6e 01 0f 1f 44 00 00 4c 39 e9 ?? ?? 44 88 64 24 43 4c 89 9c 24 c8 00 00 00 48 89 d8 4c 89 eb bf 01 } //15
		$a_03_1 = {48 8d 3c 30 83 3f 00 ?? ?? 8b 7f 04 85 ff ?? ?? 4c 8d 47 f8 48 8d 34 30 48 8d 76 08 49 d1 e8 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}