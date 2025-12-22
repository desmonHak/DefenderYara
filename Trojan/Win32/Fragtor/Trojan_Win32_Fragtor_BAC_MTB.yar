
rule Trojan_Win32_Fragtor_BAC_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.BAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {0f be 10 33 da 8b 45 fc 50 8b 4d 08 e8 ?? ?? ?? ?? 88 18 eb } //2
		$a_81_1 = {63 6d 64 20 2f 63 20 74 69 6d 65 6f 75 74 20 2f 74 20 35 20 3e 20 6e 75 6c 20 26 26 20 64 65 6c } //1 cmd /c timeout /t 5 > nul && del
		$a_81_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 41 } //1 ShellExecuteA
	condition:
		((#a_03_0  & 1)*2+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=4
 
}