
rule Trojan_Win32_FakeAV_MX_MTB{
	meta:
		description = "Trojan:Win32/FakeAV.MX!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4a 55 4d 50 40 40 59 49 4b 4b 4b 40 5a } //1 JUMP@@YIKKK@Z
		$a_01_1 = {77 73 6d 74 35 2e 65 78 65 } //1 wsmt5.exe
		$a_01_2 = {58 00 62 00 6c 00 40 00 59 00 63 00 6d 00 41 00 5a 00 64 00 6e 00 42 00 5b 00 65 00 6f 00 43 00 } //1 Xbl@YcmAZdnB[eoC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}