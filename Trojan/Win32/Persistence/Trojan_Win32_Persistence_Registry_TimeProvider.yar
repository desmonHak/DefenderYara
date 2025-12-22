
rule Trojan_Win32_Persistence_Registry_TimeProvider{
	meta:
		description = "Trojan:Win32/Persistence.Registry.TimeProvider.B,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {20 00 69 00 6d 00 70 00 6f 00 72 00 74 00 20 00 } //1  import 
		$a_00_1 = {73 00 62 00 5f 00 } //1 sb_
		$a_00_2 = {73 00 62 00 72 00 65 00 67 00 2e 00 72 00 65 00 67 00 } //1 sbreg.reg
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}