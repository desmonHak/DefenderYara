
rule Trojan_Win64_ClipBanker_NR_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.NR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 1d ee 07 20 00 48 8b 0d ef 07 20 00 31 c0 48 8d 3d 70 25 06 00 be 01 00 00 00 4c 8d 05 f4 78 06 00 41 b9 14 00 00 00 } //2
		$a_01_1 = {48 8b 8c 24 c0 00 00 00 48 8b 09 48 89 08 48 8b 0d 08 fb 1f 00 48 89 c3 bf 01 00 00 00 48 89 c8 48 89 f9 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}