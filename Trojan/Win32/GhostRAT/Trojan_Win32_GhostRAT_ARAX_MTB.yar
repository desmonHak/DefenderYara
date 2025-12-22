
rule Trojan_Win32_GhostRAT_ARAX_MTB{
	meta:
		description = "Trojan:Win32/GhostRAT.ARAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 62 75 69 6c 64 62 6f 74 5c 62 75 69 6c 64 31 5c 64 65 73 6b 74 6f 70 5f 73 63 72 65 65 6e 5c 62 75 69 6c 64 5c 62 69 6e 5c 61 63 74 69 76 65 5f 64 65 73 6b 74 6f 70 5f 6c 61 75 6e 63 68 65 72 2e 70 64 62 } //3 :\buildbot\build1\desktop_screen\build\bin\active_desktop_launcher.pdb
		$a_01_1 = {3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 52 61 6e 64 6f 6d 46 6f 6c 64 65 72 5f } //3 :\Program Files\RandomFolder_
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}