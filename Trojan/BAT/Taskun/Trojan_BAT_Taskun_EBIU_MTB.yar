
rule Trojan_BAT_Taskun_EBIU_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EBIU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 17 13 05 2b be 16 0a 18 13 05 2b b7 04 03 61 1f 4d 59 06 61 45 01 00 00 00 06 00 00 00 1f 0b 13 05 2b a0 1b 2b f9 14 0b 11 06 1f 15 93 ?? ?? ?? ?? ?? 59 13 05 2b 8c 02 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}