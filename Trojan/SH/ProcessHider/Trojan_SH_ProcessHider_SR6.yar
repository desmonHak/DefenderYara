
rule Trojan_SH_ProcessHider_SR6{
	meta:
		description = "Trojan:SH/ProcessHider.SR6,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {65 00 63 00 68 00 6f 00 20 00 22 00 2f 00 75 00 73 00 72 00 2f 00 6c 00 6f 00 63 00 61 00 6c 00 2f 00 6c 00 69 00 62 00 2f 00 6c 00 69 00 62 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00 68 00 69 00 64 00 65 00 72 00 2e 00 73 00 6f 00 22 00 20 00 3e 00 [0-02] 2f 00 65 00 74 00 63 00 2f 00 6c 00 64 00 2e 00 73 00 6f 00 2e 00 70 00 72 00 65 00 6c 00 6f 00 61 00 64 00 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}