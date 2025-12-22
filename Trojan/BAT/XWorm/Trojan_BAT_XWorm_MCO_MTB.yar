
rule Trojan_BAT_XWorm_MCO_MTB{
	meta:
		description = "Trojan:BAT/XWorm.MCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {1f 42 61 d1 6f ?? 00 00 0a 26 00 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 0d 09 } //1
		$a_01_1 = {36 00 36 00 32 00 78 00 6d 00 6d 00 73 00 74 00 77 00 6c 00 73 00 77 00 76 00 6c 00 70 00 76 00 76 00 6c 00 76 00 76 00 6d 00 72 00 6c 00 7a 00 6c 00 36 00 } //1 662xmmstwlswvlpvvlvvmrlzl6
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}