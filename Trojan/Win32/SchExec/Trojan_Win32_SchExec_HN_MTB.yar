
rule Trojan_Win32_SchExec_HN_MTB{
	meta:
		description = "Trojan:Win32/SchExec.HN!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 } //1 schtasks /create
		$a_02_1 = {5c 00 66 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b 00 5c 00 76 00 34 00 [0-12] 5c 00 6d 00 73 00 62 00 75 00 69 00 6c 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 72 00 6c 00 20 00 68 00 69 00 67 00 68 00 65 00 73 00 74 00 20 00 2f 00 66 00 } //10
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*10) >=11
 
}