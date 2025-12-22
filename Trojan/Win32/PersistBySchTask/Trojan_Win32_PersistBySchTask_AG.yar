
rule Trojan_Win32_PersistBySchTask_AG{
	meta:
		description = "Trojan:Win32/PersistBySchTask.AG,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 20 00 2f 00 74 00 6e 00 } //1 schtasks.exe /create /tn
	condition:
		((#a_00_0  & 1)*1) >=1
 
}