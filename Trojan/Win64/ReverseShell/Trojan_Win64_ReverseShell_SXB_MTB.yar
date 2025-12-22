
rule Trojan_Win64_ReverseShell_SXB_MTB{
	meta:
		description = "Trojan:Win64/ReverseShell.SXB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 63 d0 48 8b 45 ?? 48 01 c2 0f b6 45 ?? 88 02 48 8b 45 ?? 48 89 c1 e8 ?? ?? ?? ?? 88 45 ?? 80 7d ?? ?? 74 0b 8b 45 ?? 48 98 48 3b 45 } //6
		$a_03_1 = {48 98 0f b6 84 05 40 11 00 00 3c ?? 75 13 8b 85 48 21 00 00 83 e8 ?? 48 98 c6 84 05 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}