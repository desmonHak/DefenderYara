
rule Trojan_Win32_ClipBanker_ARR_MTB{
	meta:
		description = "Trojan:Win32/ClipBanker.ARR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 "
		
	strings :
		$a_01_0 = {f7 31 00 00 fb 31 00 00 06 32 00 00 12 32 00 00 27 32 00 } //10
		$a_03_1 = {48 8b 44 24 38 48 8d 44 00 ?? 89 44 24 28 48 8b 44 24 68 48 89 44 24 20 } //5
	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*5) >=15
 
}