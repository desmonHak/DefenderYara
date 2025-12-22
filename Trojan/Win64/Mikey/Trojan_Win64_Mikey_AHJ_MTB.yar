
rule Trojan_Win64_Mikey_AHJ_MTB{
	meta:
		description = "Trojan:Win64/Mikey.AHJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {0b 01 0e 25 00 76 02 00 00 28 06 00 00 00 00 00 00 ?? ?? 00 00 10 } //30
		$a_01_1 = {56 80 08 00 6a 00 00 00 00 70 08 00 10 03 } //20
		$a_01_2 = {2e 69 64 61 74 61 20 20 00 10 00 00 00 80 08 00 00 02 00 00 00 a6 05 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}