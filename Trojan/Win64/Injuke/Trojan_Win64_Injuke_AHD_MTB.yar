
rule Trojan_Win64_Injuke_AHD_MTB{
	meta:
		description = "Trojan:Win64/Injuke.AHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {4c 8b c1 49 d1 e8 4d 8b c8 4d 03 c9 4e 39 24 ca 73 ?? 4a 8d 14 ca 48 83 c2 ?? 48 83 c8 ?? 49 2b c0 48 03 c8 eb } //30
		$a_03_1 = {8b 42 0c 48 03 05 ?? ?? ?? ?? 4c 8d 45 ?? 33 d2 48 8b ce ff d0 8b f8 eb } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}