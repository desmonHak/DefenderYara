
rule Trojan_Win32_GhostRat_GMX_MTB{
	meta:
		description = "Trojan:Win32/GhostRat.GMX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 40 68 00 10 00 00 57 6a 00 ff 15 ?? ?? ?? ?? 8b d8 89 5d e8 6a 00 85 db } //10
		$a_01_1 = {66 73 2d 69 6d 2d 6b 65 66 75 2e 37 6d 6f 6f 72 2d 66 73 31 2e 63 6f 6d } //1 fs-im-kefu.7moor-fs1.com
		$a_01_2 = {5c 44 6f 63 75 6d 65 6e 74 73 5c 73 68 65 6c 6c 2e 74 78 74 } //1 \Documents\shell.txt
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}