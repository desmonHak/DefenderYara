
rule Trojan_Win32_Midie_LMC_MTB{
	meta:
		description = "Trojan:Win32/Midie.LMC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 01 00 00 "
		
	strings :
		$a_03_0 = {81 e2 00 00 00 80 09 c2 89 d1 89 c8 d1 e8 8b 14 ?? ?? ?? ?? ?? 31 d0 89 ca 83 e2 01 8b 14 95 40 04 41 00 31 c2 } //30
	condition:
		((#a_03_0  & 1)*30) >=30
 
}