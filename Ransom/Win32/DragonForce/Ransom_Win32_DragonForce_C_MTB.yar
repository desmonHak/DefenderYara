
rule Ransom_Win32_DragonForce_C_MTB{
	meta:
		description = "Ransom:Win32/DragonForce.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 8c 1c ?? ?? ?? ?? 83 e9 ?? 6b c9 ?? 89 c8 f7 ee 89 c8 c1 f8 ?? 01 ca c1 fa ?? 29 c2 89 d0 c1 e0 ?? 29 d0 29 c1 83 c1 ?? 89 c8 f7 ee 89 c8 c1 f8 ?? 01 ca c1 fa ?? 29 c2 89 d0 c1 e0 ?? 29 d0 29 c1 88 8c 1c ?? ?? ?? ?? 83 c3 01 83 fb ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}