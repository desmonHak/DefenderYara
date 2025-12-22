
rule Trojan_Win64_ValleyRat_BRS_MTB{
	meta:
		description = "Trojan:Win64/ValleyRat.BRS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 30 14 0e 48 83 c6 01 48 39 f2 75 f3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}