
rule Trojan_Win64_Rhadamanthys_MK_MTB{
	meta:
		description = "Trojan:Win64/Rhadamanthys.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 21 88 01 4d 8d 6d 00 90 4d 8d 36 48 83 c1 01 4c 39 c1 75 } //25
	condition:
		((#a_01_0  & 1)*25) >=25
 
}