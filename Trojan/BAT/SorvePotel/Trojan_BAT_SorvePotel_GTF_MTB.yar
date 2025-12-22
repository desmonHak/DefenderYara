
rule Trojan_BAT_SorvePotel_GTF_MTB{
	meta:
		description = "Trojan:BAT/SorvePotel.GTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 e8 03 00 00 28 ?? ?? ?? 0a 07 17 58 0b 07 1f 1e 32 10 28 ?? 00 00 06 2d 07 16 80 ?? 00 00 04 2a 16 0b 7e ?? 00 00 04 2d d6 } //5
		$a_03_1 = {06 0b 07 28 ?? 00 00 06 0c 08 20 ?? ?? ?? ?? 5f 2c 5c 08 17 5f 2c 57 07 28 ?? 00 00 06 2d 4f 07 28 ?? 00 00 06 2d 47 07 28 ?? 00 00 06 0d 09 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}