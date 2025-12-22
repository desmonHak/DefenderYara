
rule Trojan_BAT_Mardom_TRW_MTB{
	meta:
		description = "Trojan:BAT/Mardom.TRW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 02 11 03 11 09 6f 0a 00 00 0a 13 05 20 03 00 00 00 38 04 fc ff ff dd 82 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}