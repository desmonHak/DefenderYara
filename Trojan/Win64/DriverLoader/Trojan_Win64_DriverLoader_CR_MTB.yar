
rule Trojan_Win64_DriverLoader_CR_MTB{
	meta:
		description = "Trojan:Win64/DriverLoader.CR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 8b 79 20 45 85 e4 75 09 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}