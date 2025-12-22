
rule Trojan_Win32_Staser_LM_MTB{
	meta:
		description = "Trojan:Win32/Staser.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 04 58 8b 5d c8 89 03 8b 5d ec e8 ?? ?? ?? ?? b8 02 00 00 00 3b c1 7c ?? 68 55 03 00 00 68 ce 1f 01 04 68 01 00 00 00 e8 } //10
		$a_01_1 = {78 63 6f 6d 77 2e 65 78 65 } //5 xcomw.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5) >=10
 
}