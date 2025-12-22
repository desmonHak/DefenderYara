
rule Trojan_Win32_UacBypass_PB_MTB{
	meta:
		description = "Trojan:Win32/UacBypass.PB!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 52 00 75 00 6e 00 20 00 2f 00 69 00 20 00 2f 00 54 00 4e 00 } //2 schtasks /Run /i /TN
		$a_00_1 = {5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 44 00 69 00 73 00 6b 00 43 00 6c 00 65 00 61 00 6e 00 75 00 70 00 5c 00 53 00 69 00 6c 00 65 00 6e 00 74 00 43 00 6c 00 65 00 61 00 6e 00 75 00 70 00 } //1 \Microsoft\Windows\DiskCleanup\SilentCleanup
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1) >=3
 
}