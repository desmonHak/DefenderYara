
rule Trojan_Win32_Ekstak_NE_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.NE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 ff 3b c1 75 30 8d 44 89 50 c1 e0 02 50 ff 35 64 2e a6 00 57 ff 35 88 30 a6 00 ff 15 e4 c1 65 00 3b c7 74 61 83 05 50 2e a6 00 10 a3 64 2e a6 00 a1 60 2e a6 00 } //2
		$a_01_1 = {83 4e 08 ff 89 3e 89 7e 04 ff 05 60 2e a6 00 8b 46 10 83 08 ff 8b c6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}