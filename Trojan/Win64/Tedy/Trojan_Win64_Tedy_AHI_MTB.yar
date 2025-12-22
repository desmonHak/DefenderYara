
rule Trojan_Win64_Tedy_AHI_MTB{
	meta:
		description = "Trojan:Win64/Tedy.AHI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 c6 04 24 ?? 48 c1 e9 ?? 6b c9 ?? 29 c8 8d 4c 06 ?? 83 c0 ?? 89 4d 00 83 f8 ?? 0f } //30
		$a_03_1 = {4e 8d 24 03 41 88 2a 48 8d 2c 13 41 88 0b 41 88 01 83 ff ?? 0f } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}