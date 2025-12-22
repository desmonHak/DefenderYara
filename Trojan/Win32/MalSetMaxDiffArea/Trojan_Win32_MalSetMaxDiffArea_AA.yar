
rule Trojan_Win32_MalSetMaxDiffArea_AA{
	meta:
		description = "Trojan:Win32/MalSetMaxDiffArea.AA,SIGNATURE_TYPE_CMDHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 00 6f 00 63 00 74 00 6c 00 5f 00 76 00 6f 00 6c 00 73 00 6e 00 61 00 70 00 5f 00 73 00 65 00 74 00 5f 00 6d 00 61 00 78 00 5f 00 64 00 69 00 66 00 66 00 5f 00 61 00 72 00 65 00 61 00 5f 00 73 00 69 00 7a 00 65 00 2e 00 65 00 78 00 65 00 } //1 ioctl_volsnap_set_max_diff_area_size.exe
	condition:
		((#a_00_0  & 1)*1) >=1
 
}