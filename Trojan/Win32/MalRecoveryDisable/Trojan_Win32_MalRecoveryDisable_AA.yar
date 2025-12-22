
rule Trojan_Win32_MalRecoveryDisable_AA{
	meta:
		description = "Trojan:Win32/MalRecoveryDisable.AA,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 } //1 bcdedit
		$a_00_1 = {2f 00 73 00 65 00 74 00 } //1 /set
		$a_00_2 = {72 00 65 00 63 00 6f 00 76 00 65 00 72 00 79 00 65 00 6e 00 61 00 62 00 6c 00 65 00 64 00 20 00 6e 00 6f 00 } //1 recoveryenabled no
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}