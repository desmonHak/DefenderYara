
rule Trojan_Win64_DCRat_CR_MTB{
	meta:
		description = "Trojan:Win64/DCRat.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 8d 34 5b 48 8b 34 f2 48 89 34 d8 48 ff c3 48 39 cb 7c ec } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}