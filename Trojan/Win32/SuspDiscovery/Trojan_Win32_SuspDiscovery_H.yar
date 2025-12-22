
rule Trojan_Win32_SuspDiscovery_H{
	meta:
		description = "Trojan:Win32/SuspDiscovery.H,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {73 63 68 74 61 73 6b 73 2e 65 78 65 } //schtasks.exe  1
		$a_00_1 = {2f 00 52 00 75 00 6e 00 } //1 /Run
		$a_00_2 = {2f 00 74 00 6e 00 } //1 /tn
		$a_80_3 = {4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 4d 61 69 6e 74 65 6e 61 6e 63 65 5c 57 69 6e 69 6e 65 74 } //Microsoft\Windows\Maintenance\Wininet  1
	condition:
		((#a_80_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}