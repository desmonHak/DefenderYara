
rule Trojan_BAT_Quasar_ATBB_MTB{
	meta:
		description = "Trojan:BAT/Quasar.ATBB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 08 11 0a 11 08 11 0a 91 11 06 11 0a 11 06 8e 69 5d 91 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 08 8e 69 32 dc 11 06 16 91 13 0b 11 06 17 11 06 16 11 06 8e 69 17 59 28 ?? 00 00 0a 11 06 11 06 8e 69 17 59 11 0b 9c 11 09 17 58 13 09 11 09 19 32 aa } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}