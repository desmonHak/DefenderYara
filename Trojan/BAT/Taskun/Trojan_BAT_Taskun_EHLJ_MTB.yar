
rule Trojan_BAT_Taskun_EHLJ_MTB{
	meta:
		description = "Trojan:BAT/Taskun.EHLJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 0c 11 0d 17 58 1d 5a 07 11 0b 11 0d 58 07 8e 69 5d 94 61 58 13 0c 02 11 0b 11 0d } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}