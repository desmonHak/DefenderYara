
rule Trojan_Win32_Injuke_KK_MTB{
	meta:
		description = "Trojan:Win32/Injuke.KK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 f9 4f 31 18 89 cf 4f 81 c0 ?? 00 00 00 4f 89 c9 39 d0 } //20
	condition:
		((#a_03_0  & 1)*20) >=20
 
}