
rule Trojan_Win64_Barys_ARA_MTB{
	meta:
		description = "Trojan:Win64/Barys.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e8 1e 33 c1 69 d0 65 89 07 6c 41 03 d0 42 89 54 83 04 8b ca 49 ff c0 49 81 f8 70 02 00 00 72 dd } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}