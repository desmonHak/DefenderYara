
rule Trojan_Win32_SchExec_HM_MTB{
	meta:
		description = "Trojan:Win32/SchExec.HM!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {24 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 70 00 61 00 74 00 68 00 20 00 3d 00 20 00 27 00 63 00 3a 00 5c 00 75 00 73 00 65 00 72 00 73 00 5c 00 70 00 75 00 62 00 6c 00 69 00 63 00 5c 00 6d 00 75 00 73 00 69 00 63 00 5c 00 [0-48] 2e 00 65 00 78 00 65 00 27 00 3b 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}