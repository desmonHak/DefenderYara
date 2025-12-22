
rule Trojan_BAT_PureLogStealer_ZJK_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.ZJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0a 06 8e 69 8d ?? 00 00 01 0b 16 0c 2b 0e 07 08 06 08 91 1f 5a 61 d1 9d 08 17 58 0c 08 06 8e 69 32 ec } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}