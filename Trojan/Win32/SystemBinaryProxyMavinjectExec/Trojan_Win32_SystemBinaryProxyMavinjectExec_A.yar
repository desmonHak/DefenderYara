
rule Trojan_Win32_SystemBinaryProxyMavinjectExec_A{
	meta:
		description = "Trojan:Win32/SystemBinaryProxyMavinjectExec.A,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6d 00 61 00 76 00 69 00 6e 00 6a 00 65 00 63 00 74 00 } //1 mavinject
		$a_00_1 = {20 00 2f 00 69 00 6e 00 6a 00 65 00 63 00 74 00 72 00 75 00 6e 00 6e 00 69 00 6e 00 67 00 20 00 } //1  /injectrunning 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}