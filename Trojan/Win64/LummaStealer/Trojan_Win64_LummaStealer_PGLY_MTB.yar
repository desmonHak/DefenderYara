
rule Trojan_Win64_LummaStealer_PGLY_MTB{
	meta:
		description = "Trojan:Win64/LummaStealer.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 d1 81 f1 ?? ?? ?? ?? 31 c8 85 c8 0f 94 c1 0f 95 c0 83 fb ?? 0f 9f c2 83 fb ?? 0f 9c c3 20 c3 20 d1 08 d9 89 d3 20 c3 30 c2 08 da 89 d0 30 c8 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}