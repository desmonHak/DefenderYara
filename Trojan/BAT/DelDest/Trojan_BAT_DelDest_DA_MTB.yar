
rule Trojan_BAT_DelDest_DA_MTB{
	meta:
		description = "Trojan:BAT/DelDest.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 2c 2e 00 73 [0-03] 0a 0c 08 17 1f 64 6f [0-03] 0a 0d 09 1f 50 fe 02 13 04 11 04 2c 11 00 28 [0-03] 0a 13 05 11 05 6f [0-03] 0a 00 00 00 02 13 06 2b 00 11 06 2a } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}