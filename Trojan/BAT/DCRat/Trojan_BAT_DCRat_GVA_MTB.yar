
rule Trojan_BAT_DCRat_GVA_MTB{
	meta:
		description = "Trojan:BAT/DCRat.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 07 08 28 04 00 00 06 0d } //2
		$a_01_1 = {0a 16 0b 2b 15 00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d e1 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}