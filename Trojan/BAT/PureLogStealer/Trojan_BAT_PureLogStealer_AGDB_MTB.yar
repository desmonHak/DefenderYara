
rule Trojan_BAT_PureLogStealer_AGDB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AGDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 09 11 06 58 06 19 5f 58 61 0b 02 11 06 11 09 6f ?? 00 00 0a 13 0a 04 03 6f ?? 00 00 0a 59 13 0b 11 0b 13 0c 11 0c 19 31 03 19 13 0c 11 0c 16 2f 03 16 13 0c 19 8d ?? 00 00 01 13 0d 11 0d 16 12 0a 28 ?? 00 00 0a 9c 11 0d 17 12 0a 28 ?? 00 00 0a 9c 11 0d 18 12 0a 28 ?? 00 00 0a 9c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}