
rule Trojan_Win32_PureLog_B_AMTB{
	meta:
		description = "Trojan:Win32/PureLog.B!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {68 74 74 70 3a 2f 2f 70 6f 6f 6c 66 72 65 73 68 73 74 65 70 2e 63 6f 6d 2f 65 6e 63 68 61 6e 74 72 65 73 73 } //http://poolfreshstep.com/enchantress  1
		$a_80_1 = {41 72 6c 61 69 2e 70 64 62 } //Arlai.pdb  1
		$a_80_2 = {44 6f 77 6e 6c 6f 61 64 44 61 74 61 } //DownloadData  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}