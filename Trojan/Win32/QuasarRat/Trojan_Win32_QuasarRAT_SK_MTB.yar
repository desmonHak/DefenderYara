
rule Trojan_Win32_QuasarRAT_SK_MTB{
	meta:
		description = "Trojan:Win32/QuasarRAT.SK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {46 0f b6 4c 04 5c 4e 8d 14 00 41 83 e2 7f 45 31 ca 48 89 c1 83 e1 01 41 d3 e2 46 88 54 04 5c 48 83 f8 01 75 10 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}