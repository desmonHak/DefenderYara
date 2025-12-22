
rule Trojan_Win32_Small_AHB_MTB{
	meta:
		description = "Trojan:Win32/Small.AHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 89 da 59 74 ?? 29 f8 ba ?? 00 00 00 83 c0 ?? 89 d1 99 f7 f9 0f be 54 2a b4 8d 65 f4 89 d0 } //20
		$a_03_1 = {0f be d9 38 c1 74 ?? 42 0f b6 02 84 c0 74 ?? 0f be c0 39 d8 eb ?? 3a 0a 89 d0 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*30) >=50
 
}