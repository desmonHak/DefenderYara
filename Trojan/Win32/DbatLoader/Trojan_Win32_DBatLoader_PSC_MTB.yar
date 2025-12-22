
rule Trojan_Win32_DBatLoader_PSC_MTB{
	meta:
		description = "Trojan:Win32/DBatLoader.PSC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 69 63 6f 40 6d 62 6f 78 2e 34 6e 65 74 2e 69 74 } //1 rico@mbox.4net.it
		$a_01_1 = {57 49 4e 4e 54 } //1 WINNT
		$a_01_2 = {65 63 68 6f 61 6c 70 68 61 62 65 74 61 20 67 61 6d 61 73 65 78 6f 6b 6f 73 6f 74 65 7a 6f } //1 echoalphabeta gamasexokosotezo
		$a_01_3 = {4e 6f 74 65 70 61 64 2e 65 78 65 } //1 Notepad.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}