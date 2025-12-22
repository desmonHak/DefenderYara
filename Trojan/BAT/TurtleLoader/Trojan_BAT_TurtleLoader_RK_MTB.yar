
rule Trojan_BAT_TurtleLoader_RK_MTB{
	meta:
		description = "Trojan:BAT/TurtleLoader.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 5f 57 65 62 5f 64 62 71 74 79 73 76 79 2e 64 6c 6c } //1 App_Web_dbqtysvy.dll
		$a_01_1 = {4d 65 74 65 72 70 72 65 74 65 72 53 68 65 6c 6c } //1 MeterpreterShell
		$a_00_2 = {53 00 68 00 65 00 6c 00 6c 00 63 00 6f 00 64 00 65 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 64 00 } //1 Shellcode executed
		$a_01_3 = {67 65 74 5f 52 65 73 70 6f 6e 73 65 20 57 72 69 74 65 } //1 get_Response Write
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}