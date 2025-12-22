
rule Trojan_BAT_Quasar_ALKB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ALKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 12 07 11 09 07 91 11 11 07 11 11 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 11 09 8e 69 fe 04 13 15 11 15 2d dc } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}