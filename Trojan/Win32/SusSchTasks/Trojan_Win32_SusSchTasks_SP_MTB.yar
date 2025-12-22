
rule Trojan_Win32_SusSchTasks_SP_MTB{
	meta:
		description = "Trojan:Win32/SusSchTasks.SP!MTB,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 } //1 powershell
		$a_00_1 = {4e 00 6f 00 50 00 72 00 6f 00 66 00 69 00 6c 00 65 00 } //1 NoProfile
		$a_00_2 = {53 00 74 00 61 00 72 00 74 00 2d 00 53 00 63 00 68 00 65 00 64 00 75 00 6c 00 65 00 64 00 54 00 61 00 73 00 6b 00 } //1 Start-ScheduledTask
		$a_00_3 = {53 00 74 00 61 00 74 00 65 00 52 00 65 00 70 00 6f 00 73 00 69 00 74 00 6f 00 72 00 79 00 73 00 } //1 StateRepositorys
		$a_00_4 = {54 00 61 00 73 00 6b 00 4e 00 61 00 6d 00 65 00 } //1 TaskName
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}