
rule Trojan_BAT_Heracles_AMX_MTB{
	meta:
		description = "Trojan:BAT/Heracles.AMX!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 03 11 04 6f 3d 00 00 0a 6f 3e 00 00 0a 11 04 17 58 13 04 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}