
rule Trojan_Win32_DllExecuteAbuse_A{
	meta:
		description = "Trojan:Win32/DllExecuteAbuse.A,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 [0-f0] 72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 5f 00 64 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 20 00 77 00 72 00 69 00 74 00 65 00 74 00 6f 00 74 00 65 00 6d 00 70 00 66 00 69 00 6c 00 65 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}