
rule Trojan_BAT_ClipBanker_ANCB_MTB{
	meta:
		description = "Trojan:BAT/ClipBanker.ANCB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_03_0 = {07 11 06 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 11 06 1e 63 13 06 } //4
		$a_03_1 = {07 11 07 6f ?? 00 00 0a 1f 3a 5a 11 06 58 13 08 } //2
		$a_01_2 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 } //1 Confuser.Core
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=7
 
}