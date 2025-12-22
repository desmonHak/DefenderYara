
rule Trojan_BAT_StrelaStealer_MTH_MTB{
	meta:
		description = "Trojan:BAT/StrelaStealer.MTH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_81_0 = {53 74 65 61 6c 65 72 43 72 79 70 74 2e 65 78 65 } //1 StealerCrypt.exe
		$a_01_1 = {62 37 37 61 35 63 35 36 31 39 33 34 65 30 38 39 } //2 b77a5c561934e089
	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}