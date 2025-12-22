
rule Trojan_Win32_Qukart_GZF_MTB{
	meta:
		description = "Trojan:Win32/Qukart.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 d0 31 00 00 00 b0 02 00 d0 31 00 } //10
		$a_01_1 = {00 49 69 63 4d 57 4e 59 71 93 19 00 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=20
 
}
rule Trojan_Win32_Qukart_GZF_MTB_2{
	meta:
		description = "Trojan:Win32/Qukart.GZF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 02 85 8b 79 6a a0 8b cf ?? ?? 65 56 81 74 04 ?? 81 68 45 52 ?? ?? 52 c5 a8 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}