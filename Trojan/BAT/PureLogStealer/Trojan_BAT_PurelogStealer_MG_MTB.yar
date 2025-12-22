
rule Trojan_BAT_PurelogStealer_MG_MTB{
	meta:
		description = "Trojan:BAT/PurelogStealer.MG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 72 61 00 00 70 28 09 00 00 0a 6f 0a 00 00 0a 00 06 72 bb 00 00 70 28 09 00 00 0a 6f 0b 00 00 0a 00 06 6f 0c 00 00 0a 0b 73 0d 00 00 0a 0c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}