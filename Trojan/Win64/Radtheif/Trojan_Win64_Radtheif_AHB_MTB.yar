
rule Trojan_Win64_Radtheif_AHB_MTB{
	meta:
		description = "Trojan:Win64/Radtheif.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 94 24 f0 00 00 00 4c 8b 9c 24 d8 00 00 00 44 0f b6 64 24 43 48 89 c6 48 89 cb 48 8b 44 24 50 48 8b 4c 24 60 e9 } //20
		$a_01_1 = {48 8d 34 d9 48 8b 38 48 89 3c 30 48 ff c3 48 8d 72 ff 48 39 f3 7c } //30
	condition:
		((#a_01_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}