
rule Trojan_Win64_Radtheif_AHF_MTB{
	meta:
		description = "Trojan:Win64/Radtheif.AHF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,3c 00 3c 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 99 f6 42 d4 95 b7 ?? 87 17 a5 93 44 33 5b 0c 7f fb } //30
		$a_03_1 = {f2 52 29 45 ?? a5 95 f6 37 a6 b8 } //20
		$a_01_2 = {51 65 ee 0a 3a 5d 93 6c 53 2d } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20+(#a_01_2  & 1)*10) >=60
 
}