
rule Trojan_Win32_SalatStealer_NE_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 07 09 c0 74 3c 8b 5f 04 8d 84 30 00 b0 c3 00 01 f3 50 83 c7 08 ff 96 28 b0 c3 00 95 8a 07 47 08 c0 74 dc } //1
		$a_01_1 = {47 6f 20 62 75 69 6c 64 20 49 44 } //1 Go build ID
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}