
rule Trojan_Win32_Oader_CG_MTB{
	meta:
		description = "Trojan:Win32/Oader.CG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 24 1e 30 c4 04 ?? 32 24 1f 8b 7d ?? 43 83 fb ?? 88 24 0f 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}