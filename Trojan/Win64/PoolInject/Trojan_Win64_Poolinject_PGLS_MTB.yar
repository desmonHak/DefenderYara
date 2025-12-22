
rule Trojan_Win64_Poolinject_PGLS_MTB{
	meta:
		description = "Trojan:Win64/Poolinject.PGLS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c6 89 f0 c1 e8 ?? 0f b6 ca 4c 8b 9c 24 ?? ?? ?? ?? 43 0f b6 14 03 31 ca 31 c2 31 f2 43 88 14 03 c1 c5 ?? 31 f5 45 01 d2 43 8d 0c 52 41 d3 e1 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}