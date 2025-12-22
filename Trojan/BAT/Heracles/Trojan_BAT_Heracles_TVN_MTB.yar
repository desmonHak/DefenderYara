
rule Trojan_BAT_Heracles_TVN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.TVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 09 18 5d 58 0c 07 09 06 09 91 03 09 20 ?? 00 00 00 5d 58 61 d2 9c 00 09 17 58 0d 09 06 8e 69 fe 04 13 04 11 04 2d } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}