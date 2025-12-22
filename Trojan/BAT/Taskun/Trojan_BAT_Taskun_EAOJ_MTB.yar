
rule Trojan_BAT_Taskun_EAOJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EAOJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 11 0c 11 1e 1f 11 5a 58 13 1f 00 02 11 1d 11 1e ?? ?? ?? ?? ?? 13 20 04 03 ?? ?? ?? ?? ?? 59 13 21 11 21 13 22 11 22 19 fe 02 13 28 11 28 2c 03 19 13 22 11 22 16 fe 04 13 29 11 29 2c 03 16 13 22 11 0c 16 5f 13 23 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}