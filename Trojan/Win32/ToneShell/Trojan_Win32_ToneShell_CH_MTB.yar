
rule Trojan_Win32_ToneShell_CH_MTB{
	meta:
		description = "Trojan:Win32/ToneShell.CH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {c6 45 d4 73 c6 45 d5 68 c6 45 d6 65 c6 45 d7 6c c6 45 d8 6c c6 45 d9 33 c6 45 da 32 c6 45 db 2e c6 45 dc 64 c6 45 dd 6c c6 45 de 6c c6 45 df 00 } //2
		$a_01_1 = {47 6c 6f 62 61 6c 5c 61 62 64 66 42 73 6b 5f 6f 6e 63 65 } //1 Global\abdfBsk_once
		$a_01_2 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 66 00 6f 00 72 00 6d 00 61 00 74 00 } //1 cmd.exe /c format
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}