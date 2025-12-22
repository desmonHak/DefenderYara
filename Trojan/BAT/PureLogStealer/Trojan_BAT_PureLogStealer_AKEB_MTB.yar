
rule Trojan_BAT_PureLogStealer_AKEB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AKEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 07 09 19 5f 07 8e 69 5d 94 1f 11 5a 61 0d } //4
		$a_01_1 = {00 11 0c 11 0d 17 58 1d 5a 07 11 0b 11 0d 58 07 8e 69 5d 94 61 58 } //3
		$a_01_2 = {07 08 07 08 94 11 08 61 0e 05 1f 0f 5f 58 9e 08 17 58 07 8e 69 5d 0c } //3
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3) >=10
 
}