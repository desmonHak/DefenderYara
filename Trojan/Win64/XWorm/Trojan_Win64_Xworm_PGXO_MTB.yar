
rule Trojan_Win64_Xworm_PGXO_MTB{
	meta:
		description = "Trojan:Win64/Xworm.PGXO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 c2 44 89 c1 83 e2 ?? 83 e1 ?? 8b 14 97 c1 e1 ?? d3 ea 42 30 14 00 48 8b 06 49 83 c0 ?? 48 8b 56 ?? 48 29 c2 44 39 c2 7f } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}