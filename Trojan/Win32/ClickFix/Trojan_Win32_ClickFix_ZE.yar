
rule Trojan_Win32_ClickFix_ZE{
	meta:
		description = "Trojan:Win32/ClickFix.ZE,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //1 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 } //1 http
		$a_00_2 = {32 00 6e 00 6f 00 2e 00 63 00 6f 00 2f 00 } //1 2no.co/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule Trojan_Win32_ClickFix_ZE_2{
	meta:
		description = "Trojan:Win32/ClickFix.ZE,SIGNATURE_TYPE_CMDHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_00_0 = {6d 00 73 00 68 00 74 00 61 00 } //10 mshta
		$a_00_1 = {68 00 74 00 74 00 70 00 90 00 02 00 ff 00 2e 00 6f 00 67 00 67 00 } //10
		$a_00_2 = {20 00 05 27 20 00 } //10  ✅ 
		$a_00_3 = {6d 00 73 00 65 00 64 00 67 00 65 00 77 00 65 00 62 00 76 00 69 00 65 00 77 00 32 00 2e 00 65 00 78 00 65 00 } //-100 msedgewebview2.exe
		$a_00_4 = {61 00 74 00 74 00 72 00 69 00 62 00 2e 00 65 00 78 00 65 00 } //-100 attrib.exe
		$a_00_5 = {5c 00 45 00 64 00 67 00 65 00 5c 00 41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 5c 00 6d 00 73 00 65 00 64 00 67 00 65 00 2e 00 65 00 78 00 65 00 } //-100 \Edge\Application\msedge.exe
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*-100+(#a_00_4  & 1)*-100+(#a_00_5  & 1)*-100) >=30
 
}