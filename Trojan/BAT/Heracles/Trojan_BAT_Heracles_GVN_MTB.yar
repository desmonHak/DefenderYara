
rule Trojan_BAT_Heracles_GVN_MTB{
	meta:
		description = "Trojan:BAT/Heracles.GVN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 06 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 72 } //2
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //2 FromBase64String
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}