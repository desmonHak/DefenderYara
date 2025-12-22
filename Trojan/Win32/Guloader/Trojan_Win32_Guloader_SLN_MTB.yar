
rule Trojan_Win32_Guloader_SLN_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 00 65 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 20 00 66 00 6c 00 6f 00 6b 00 73 00 69 00 6c 00 6b 00 65 00 72 00 6e 00 65 00 73 00 20 00 67 00 69 00 73 00 66 00 6d 00 6c 00 65 00 } //2 fellation floksilkernes gisfmle
		$a_01_1 = {73 00 6c 00 65 00 65 00 76 00 65 00 64 00 20 00 72 00 6f 00 74 00 69 00 66 00 65 00 72 00 61 00 6c 00 20 00 73 00 74 00 69 00 6e 00 6b 00 62 00 65 00 72 00 72 00 79 00 } //2 sleeved rotiferal stinkberry
		$a_01_2 = {77 00 68 00 6f 00 6c 00 65 00 73 00 61 00 6c 00 65 00 6c 00 79 00 20 00 6b 00 61 00 75 00 74 00 69 00 6f 00 6e 00 69 00 73 00 74 00 65 00 6e 00 73 00 2e 00 65 00 78 00 65 00 } //2 wholesalely kautionistens.exe
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}