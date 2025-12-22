
rule Trojan_BAT_BPLogger_ENZX_MTB{
	meta:
		description = "Trojan:BAT/BPLogger.ENZX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 06 7b 1c 00 00 04 09 23 00 00 00 00 00 00 00 40 ?? ?? ?? ?? ?? 09 6c ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 02 6c 5b ?? ?? ?? ?? ?? 5a 03 5a a1 07 06 7b 1c 00 00 04 09 99 06 7b 1c 00 00 04 09 99 5a 58 0b 00 09 17 58 0d 09 02 fe 04 13 04 11 04 2d af } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}