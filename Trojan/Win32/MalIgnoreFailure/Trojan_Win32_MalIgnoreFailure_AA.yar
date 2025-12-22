
rule Trojan_Win32_MalIgnoreFailure_AA{
	meta:
		description = "Trojan:Win32/MalIgnoreFailure.AA,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {62 00 63 00 64 00 65 00 64 00 69 00 74 00 } //1 bcdedit
		$a_00_1 = {2f 00 73 00 65 00 74 00 } //1 /set
		$a_00_2 = {62 00 6f 00 6f 00 74 00 73 00 74 00 61 00 74 00 75 00 73 00 70 00 6f 00 6c 00 69 00 63 00 79 00 } //1 bootstatuspolicy
		$a_00_3 = {69 00 67 00 6e 00 6f 00 72 00 65 00 61 00 6c 00 6c 00 66 00 61 00 69 00 6c 00 75 00 72 00 65 00 73 00 } //1 ignoreallfailures
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}