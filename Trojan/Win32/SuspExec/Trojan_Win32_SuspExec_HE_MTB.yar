
rule Trojan_Win32_SuspExec_HE_MTB{
	meta:
		description = "Trojan:Win32/SuspExec.HE!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 20 00 6e 00 6f 00 6d 00 6f 00 72 00 65 00 72 00 61 00 6e 00 73 00 6f 00 6d 00 2e 00 [0-08] 20 00 64 00 6e 00 73 00 [0-02] 2e 00 } //1
		$a_02_1 = {6e 00 73 00 6c 00 6f 00 6f 00 6b 00 75 00 70 00 20 00 [0-20] 2e 00 [0-08] 20 00 64 00 6e 00 73 00 [0-02] 2e 00 73 00 6f 00 70 00 72 00 6f 00 64 00 6e 00 73 00 2e 00 72 00 75 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}