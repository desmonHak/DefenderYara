
rule Trojan_BAT_PureLogStealer_AGEB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AGEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? 00 06 03 08 18 58 17 59 03 8e 69 5d 91 59 20 fa 00 00 00 58 1b 58 17 58 20 00 01 00 00 5d d2 9c 08 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}