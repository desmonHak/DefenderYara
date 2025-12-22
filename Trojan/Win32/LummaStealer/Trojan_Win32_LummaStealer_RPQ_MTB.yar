
rule Trojan_Win32_LummaStealer_RPQ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.RPQ!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 20 00 69 00 63 00 61 00 63 00 6c 00 73 00 [0-70] 2e 00 65 00 78 00 65 00 20 00 2f 00 72 00 65 00 6d 00 6f 00 76 00 65 00 3a 00 64 00 20 00 65 00 76 00 65 00 72 00 79 00 6f 00 6e 00 65 00 20 00 61 00 64 00 6d 00 69 00 6e 00 69 00 73 00 74 00 72 00 61 00 74 00 6f 00 72 00 73 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}