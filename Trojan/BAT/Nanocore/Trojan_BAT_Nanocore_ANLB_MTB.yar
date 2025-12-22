
rule Trojan_BAT_Nanocore_ANLB_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.ANLB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 05 0e 04 6f ?? 00 00 0a 0a 04 03 6f ?? 00 00 0a 59 0b 07 16 fe 02 16 fe 01 0c 08 2c 02 2b 68 03 06 72 ?? ?? 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 00 07 17 59 0b 07 16 fe 02 16 fe 01 0d 09 2c 02 2b 45 03 06 72 ?? ?? 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 00 07 17 59 0b 07 16 fe 02 16 fe 01 13 04 11 04 2c 02 2b 20 03 06 72 ?? ?? 00 70 28 ?? 00 00 06 6f ?? 00 00 0a 00 0e 05 0e 06 05 0e 04 06 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}