
rule Trojan_Win32_Dofoil_MMZ_MTB{
	meta:
		description = "Trojan:Win32/Dofoil.MMZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 7d dc 8b 45 10 8b 00 2b 50 14 8b 41 0c 0f b6 04 10 89 45 e8 8b 45 0c 8b 00 8b 4d 0c 8b 09 8b 55 e4 2b 51 14 8b 40 0c 0f b6 ?? 10 33 4d e8 e8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}