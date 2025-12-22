
rule Trojan_Win32_StartPage_NP_MTB{
	meta:
		description = "Trojan:Win32/StartPage.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 45 fc 50 8b 45 fc 8d 04 86 50 56 53 e8 f5 fd ff ff 83 c4 14 8b 45 fc 48 a3 90 72 40 00 89 35 94 72 40 00 5e 5b 89 ec } //2
		$a_01_1 = {89 f9 89 f0 31 d2 f7 f1 89 d0 8a 80 00 67 40 00 88 03 8d 43 01 5f 5e 5b } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}