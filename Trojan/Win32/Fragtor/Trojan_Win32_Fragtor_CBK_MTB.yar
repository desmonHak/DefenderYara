
rule Trojan_Win32_Fragtor_CBK_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.CBK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 58 58 f9 f8 83 f7 ?? f9 f8 83 45 ?? ?? 8d 85 ?? ?? ff ff 89 44 24 ?? 8b 45 ?? 89 04 24 e8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}