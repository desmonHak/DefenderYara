
rule Trojan_Win32_SalatStealer_NRR_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.NRR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 03 00 00 "
		
	strings :
		$a_03_0 = {80 eb e8 01 f0 89 07 83 c7 05 88 d8 e2 d9 8d be 00 ?? c1 00 8b 07 09 c0 } //3
		$a_03_1 = {8a 07 47 08 c0 74 dc 89 f9 57 48 f2 ae 55 ff 96 30 ?? c3 00 09 c0 74 07 89 03 83 c3 04 eb e1 } //3
		$a_01_2 = {47 6f 20 62 75 69 6c 64 20 49 44 } //2 Go build ID
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_01_2  & 1)*2) >=8
 
}