
rule Trojan_Win32_Fragtor_SMN_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.SMN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 05 33 f0 b8 ?? ?? ?? ?? f7 e6 8b c8 b8 25 49 92 24 f7 e6 b8 ?? ?? ?? ?? 03 ca f7 e6 8b c6 d1 e9 2b c2 83 e1 ?? d1 e8 03 c2 c1 e8 03 2b c1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}