
rule Trojan_Win64_TofuStation_A_dha{
	meta:
		description = "Trojan:Win64/TofuStation.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 00 70 00 70 00 55 00 49 00 53 00 76 00 63 00 } //1 AppUISvc
		$a_01_1 = {00 77 6d 6f 6e 73 76 63 2e 64 6c 6c 00 } //1
		$a_01_2 = {00 4b 72 62 4d 61 6e } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}