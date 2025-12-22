
rule Trojan_BAT_XWorm_GAPB_MTB{
	meta:
		description = "Trojan:BAT/XWorm.GAPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 08 02 08 91 03 08 03 8e 69 5d 91 61 9c 08 } //3
	condition:
		((#a_01_0  & 1)*3) >=3
 
}