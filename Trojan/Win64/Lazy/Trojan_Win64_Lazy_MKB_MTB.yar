
rule Trojan_Win64_Lazy_MKB_MTB{
	meta:
		description = "Trojan:Win64/Lazy.MKB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8d 71 01 46 0f b6 04 08 48 39 f2 ?? ?? 48 89 44 24 58 44 88 44 24 43 48 89 4c 24 78 } //15
		$a_03_1 = {48 83 ec 48 48 89 6c 24 40 48 8d 6c 24 40 66 81 38 64 86 ?? ?? 48 8b 50 18 48 8b 70 20 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}