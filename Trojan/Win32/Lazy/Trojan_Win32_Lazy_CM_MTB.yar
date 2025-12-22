
rule Trojan_Win32_Lazy_CM_MTB{
	meta:
		description = "Trojan:Win32/Lazy.CM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {5f 6e 65 77 2e 65 78 65 } //1 _new.exe
		$a_81_1 = {4d 4c 6f 67 69 6e 2e 65 78 65 } //1 MLogin.exe
		$a_01_2 = {68 74 74 70 3a 2f 2f 31 31 30 2e 34 32 2e 34 2e 31 30 35 } //1 http://110.42.4.105
		$a_01_3 = {55 6e 61 62 6c 65 20 74 6f 20 69 6e 73 74 61 6c 6c 20 68 6f 6f 6b } //1 Unable to install hook
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}