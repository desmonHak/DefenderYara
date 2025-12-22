
rule Trojan_Win32_Persistence_LocalAccount_Group{
	meta:
		description = "Trojan:Win32/Persistence.LocalAccount.Group.Add.C,SIGNATURE_TYPE_CMDHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {6e 00 65 00 74 00 } //10 net
		$a_00_1 = {6c 00 6f 00 63 00 61 00 6c 00 67 00 72 00 6f 00 75 00 70 00 } //10 localgroup
		$a_00_2 = {70 00 6f 00 77 00 65 00 72 00 20 00 75 00 73 00 65 00 72 00 73 00 } //1 power users
		$a_00_3 = {72 00 65 00 6d 00 6f 00 74 00 65 00 20 00 64 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 75 00 73 00 65 00 72 00 73 00 } //1 remote desktop users
		$a_00_4 = {73 00 62 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 } //10 sbusername
		$a_00_5 = {2f 00 61 00 64 00 64 00 } //10 /add
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10) >=41
 
}