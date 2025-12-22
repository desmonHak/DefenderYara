
rule Trojan_BAT_Taskun_ZSP_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ZSP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {5f 91 13 0f 02 11 0d 11 0e 6f ?? 00 00 0a 13 10 04 03 6f ?? 00 00 0a 59 13 11 11 11 13 12 11 12 19 fe 02 13 13 11 13 2c 03 } //6
		$a_03_1 = {16 fe 02 13 15 11 15 2c 0e 03 12 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 17 fe 02 13 16 11 16 2c 0e 03 12 10 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 12 18 } //4
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*4) >=10
 
}