
rule Trojan_BAT_Taskun_AFDB_MTB{
	meta:
		description = "Trojan:BAT/Taskun.AFDB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_03_0 = {06 19 62 0e 04 11 07 28 ?? 00 00 06 11 07 1f 11 5a 58 61 0a 07 06 11 07 1b 5d 1f 1f 5f 63 05 11 07 19 5d 1f 1f 5f 62 61 61 0b } //5
		$a_01_1 = {07 11 06 1f 1f 5a 06 1d 5f 58 61 0b } //2 ᄇἆ娟ᴆ塟ୡ
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2) >=7
 
}