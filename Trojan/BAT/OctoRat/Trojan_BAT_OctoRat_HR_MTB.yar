
rule Trojan_BAT_OctoRat_HR_MTB{
	meta:
		description = "Trojan:BAT/OctoRat.HR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e b6 00 00 0a 72 e6 31 00 70 16 6f bb 00 00 0a de 03 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}