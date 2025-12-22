
rule Trojan_Win64_Rozena_SPZP_MTB{
	meta:
		description = "Trojan:Win64/Rozena.SPZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 31 0a 48 83 c2 08 49 3b d0 72 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}