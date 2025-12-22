
rule Trojan_Win64_Mikey_AHG_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AHG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_01_0 = {20 20 20 00 20 20 20 20 00 00 07 00 00 10 00 00 00 cc 02 00 00 10 } //10
		$a_01_1 = {c0 2e 69 64 61 74 61 20 20 00 10 00 00 00 20 07 00 00 02 00 00 00 de 02 } //20
		$a_03_2 = {2e 70 64 61 74 61 00 49 00 30 00 00 00 ?? 62 00 00 22 00 00 00 ?? 23 } //30
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*20+(#a_03_2  & 1)*30) >=60
 
}