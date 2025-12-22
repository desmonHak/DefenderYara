
rule Trojan_Win32_Lazy_PGLY_MTB{
	meta:
		description = "Trojan:Win32/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 e9 80 e5 ?? f6 d1 89 ca 80 e2 ?? 08 d5 89 c2 24 ?? 80 f2 ?? 08 d1 80 e2 ?? 08 d0 f6 d1 30 e8 08 c1 88 4c 3d 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}