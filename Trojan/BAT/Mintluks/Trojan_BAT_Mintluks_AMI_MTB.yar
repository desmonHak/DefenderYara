
rule Trojan_BAT_Mintluks_AMI_MTB{
	meta:
		description = "Trojan:BAT/Mintluks.AMI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {17 da 13 06 13 04 2b 1e 07 09 11 04 9a 02 1b 6f ?? 00 00 06 03 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 11 04 17 d6 13 04 11 04 11 06 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}