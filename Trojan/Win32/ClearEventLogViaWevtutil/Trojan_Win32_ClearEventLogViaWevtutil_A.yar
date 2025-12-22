
rule Trojan_Win32_ClearEventLogViaWevtutil_A{
	meta:
		description = "Trojan:Win32/ClearEventLogViaWevtutil.A,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_00_0 = {77 00 65 00 76 00 74 00 75 00 74 00 69 00 6c 00 2e 00 65 00 78 00 65 00 20 00 63 00 6c 00 20 00 61 00 74 00 74 00 61 00 63 00 6b 00 69 00 71 00 5f 00 } //3 wevtutil.exe cl attackiq_
	condition:
		((#a_00_0  & 1)*3) >=3
 
}