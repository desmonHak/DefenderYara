
rule Trojan_BAT_Taskun_ELHD_MTB{
	meta:
		description = "Trojan:BAT/Taskun.ELHD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 8f 0e 00 00 01 25 71 0e 00 00 01 07 09 07 8e 69 5d 91 61 d2 81 0e 00 00 01 09 17 58 0d 09 08 8e 69 32 db } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}