
rule Trojan_Win32_SusDeathStalker_B{
	meta:
		description = "Trojan:Win32/SusDeathStalker.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_80_0 = {6d 73 78 73 6c 2e 65 78 65 20 } //msxsl.exe   1
		$a_80_1 = {70 61 79 6c 6f 61 64 2e 78 6d 6c } //payload.xml  1
		$a_80_2 = {70 61 79 6c 6f 61 64 2e 78 73 6c } //payload.xsl  1
		$a_80_3 = {41 70 70 44 61 74 61 5c 4c 6f 63 61 6c 5c 54 65 6d 70 } //AppData\Local\Temp  1
		$a_80_4 = {77 69 6e 76 65 72 2e 65 78 65 } //winver.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=3
 
}