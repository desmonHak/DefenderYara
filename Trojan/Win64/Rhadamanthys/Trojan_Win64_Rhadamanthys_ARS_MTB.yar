
rule Trojan_Win64_Rhadamanthys_ARS_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {ff d1 48 8b 4c 24 18 48 01 c1 48 89 4c 24 18 48 8b 4c 24 28 48 8b 11 48 8b 0a 48 8b 44 24 20 48 8b 5c 24 10 ff d1 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}