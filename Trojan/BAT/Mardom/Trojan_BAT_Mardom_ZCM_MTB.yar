
rule Trojan_BAT_Mardom_ZCM_MTB{
	meta:
		description = "Trojan:BAT/Mardom.ZCM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0a 11 0b 1a 5a 58 13 0c 11 09 08 5a 11 0b 58 13 0d 11 04 11 0c 18 58 91 13 0e 11 05 11 0d 20 ff 00 00 00 11 0e 59 1f 72 61 d2 9c 11 0b 17 58 13 0b 11 0b 08 3f c6 ff ff ff } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}