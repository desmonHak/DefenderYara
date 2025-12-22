
rule Trojan_BAT_MassLogger_MDH_MTB{
	meta:
		description = "Trojan:BAT/MassLogger.MDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 07 20 00 2c 01 00 18 18 20 87 d6 12 00 16 28 ae 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}