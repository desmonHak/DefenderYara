
rule Trojan_BAT_PureLogStealer_AXCB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AXCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 08 1f 1f 5a 09 58 0e 05 58 61 0a 02 08 09 6f ?? 00 00 0a 13 04 04 03 6f ?? 00 00 0a 59 13 05 11 05 } //5
		$a_03_1 = {05 0e 04 6f ?? 00 00 0a 61 0a 19 8d ?? 00 00 01 0b 0e 04 2c 3f 0e 04 6f ?? 00 00 0a 16 31 35 07 16 0e 04 16 6f ?? 00 00 0a 0e 05 58 20 ff 00 00 00 5f d2 9c 07 17 06 17 62 } //2
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*2) >=7
 
}