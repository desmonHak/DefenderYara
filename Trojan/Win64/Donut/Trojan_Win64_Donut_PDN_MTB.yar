
rule Trojan_Win64_Donut_PDN_MTB{
	meta:
		description = "Trojan:Win64/Donut.PDN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 32 04 17 48 c1 e9 ?? d0 c8 41 89 ca 44 31 c0 41 83 c0 ?? 41 c1 e2 ?? 41 88 04 17 41 29 ca 89 d1 44 29 d1 48 63 c9 32 84 0c ?? ?? ?? ?? 41 88 04 17 48 83 c2 ?? 48 81 fa ?? ?? ?? ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}