
rule Trojan_Win32_Fragtor_PGFR_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.PGFR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 d2 f7 75 14 8b 45 d4 0f b6 0c 11 31 c8 88 45 df 83 3d ?? ?? ?? ?? 00 74 ?? 8a 55 df a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 ce 83 c6 01 89 35 ?? ?? ?? ?? 88 14 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}