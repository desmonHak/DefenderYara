
rule Trojan_BAT_Mardom_AD_MTB{
	meta:
		description = "Trojan:BAT/Mardom.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 41 00 00 04 20 d6 cf 66 24 65 20 cc fd 01 57 59 20 5e 32 97 84 61 7d 13 00 00 04 38 cc fb ff ff } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}