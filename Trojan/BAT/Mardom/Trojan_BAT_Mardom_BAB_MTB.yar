
rule Trojan_BAT_Mardom_BAB_MTB{
	meta:
		description = "Trojan:BAT/Mardom.BAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 91 0d 09 08 20 00 01 00 00 5d d2 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0d 09 19 63 09 1b 62 60 07 61 d2 0d 06 08 09 9c 08 17 58 0c 08 02 8e 69 32 cb } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}