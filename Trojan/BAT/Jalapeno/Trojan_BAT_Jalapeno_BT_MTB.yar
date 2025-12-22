
rule Trojan_BAT_Jalapeno_BT_MTB{
	meta:
		description = "Trojan:BAT/Jalapeno.BT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 3e 08 11 3e 6d 61 0c 08 20 c0 9d fa 88 06 58 07 58 61 0c 08 20 bb 6d 07 4d 06 61 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}