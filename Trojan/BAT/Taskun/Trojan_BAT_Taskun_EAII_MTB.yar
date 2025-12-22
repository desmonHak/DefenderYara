
rule Trojan_BAT_Taskun_EAII_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EAII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 0b 17 58 1f 25 5a 11 0e 17 58 1f 65 5a 61 07 61 13 0f 11 0f 11 0d ?? ?? ?? ?? ?? ?? ?? ?? ?? 5a 69 61 13 0f 02 11 0b 11 0e ?? ?? ?? ?? ?? 13 10 04 03 ?? ?? ?? ?? ?? 59 13 11 11 11 13 12 11 12 19 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}