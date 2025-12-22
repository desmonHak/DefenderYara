
rule Trojan_Win32_Spy_NF_MTB{
	meta:
		description = "Trojan:Win32/Spy.NF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 b0 8b 14 95 88 20 43 00 03 d1 8a 0c 03 03 d3 43 88 4c 32 2e 8b 4d bc 3b df 7c e3 } //2
		$a_01_1 = {8b 45 b4 8a 0a 88 4c 07 2e 8b 45 b0 8b 04 85 88 20 43 00 80 4c 38 2d 04 8b 45 b8 40 89 46 04 eb 08 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}