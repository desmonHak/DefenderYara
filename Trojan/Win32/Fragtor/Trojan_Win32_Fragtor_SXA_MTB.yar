
rule Trojan_Win32_Fragtor_SXA_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 03 00 00 "
		
	strings :
		$a_03_0 = {50 ff d3 85 c0 74 f3 6a ?? 8d 85 ?? ?? ?? ?? 50 8d 85 ?? ?? ?? ?? 50 ff d7 85 c0 75 09 68 ?? ?? ?? ?? ff d6 eb d4 } //30
		$a_03_1 = {50 ff d7 68 e8 03 00 00 ff d6 8d 85 ?? ?? ?? ?? 50 ff d3 85 c0 75 e3 } //15
		$a_03_2 = {2b f9 d1 ff 8b c7 8b cf 99 83 e2 ?? 03 c2 c1 f8 ?? 2b c8 83 c1 } //5
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*15+(#a_03_2  & 1)*5) >=50
 
}