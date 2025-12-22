
rule Trojan_Win64_Rhadamanthys_ARM_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.ARM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b6 54 1c 20 89 d1 44 01 d2 41 89 d0 41 c1 f8 1f 41 c1 e8 18 44 01 c2 0f b6 d2 44 29 c2 41 89 d2 48 63 d2 44 0f b6 44 14 20 46 88 44 1c 20 88 4c 14 20 42 02 4c 1c 20 0f b6 c9 0f b6 54 0c 20 30 13 48 83 c3 01 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}