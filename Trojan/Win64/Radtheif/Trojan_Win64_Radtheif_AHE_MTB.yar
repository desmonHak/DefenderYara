
rule Trojan_Win64_Radtheif_AHE_MTB{
	meta:
		description = "Trojan:Win64/Radtheif.AHE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4c 24 20 f2 0f 10 41 ?? 48 8b 54 24 28 f2 0f 10 4a ?? 66 0f 2e c8 75 } //20
		$a_03_1 = {0f b6 94 01 ?? ?? 00 00 48 8d 59 d9 48 f7 db 0f b6 9c 03 ?? ?? 00 00 01 da 88 94 ?? ?? 01 00 00 48 ff c1 48 83 f9 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}