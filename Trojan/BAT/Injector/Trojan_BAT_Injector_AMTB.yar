
rule Trojan_BAT_Injector_AMTB{
	meta:
		description = "Trojan:BAT/Injector!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {42 4c 41 43 4b 48 41 57 4b 2e 64 6c 6c } //BLACKHAWK.dll  2
		$a_80_1 = {42 4c 41 43 4b 48 41 57 4b 2e 70 64 62 } //BLACKHAWK.pdb  2
		$a_80_2 = {42 4c 41 43 4b 48 41 57 4b 2e 50 72 6f 70 65 72 74 69 65 73 } //BLACKHAWK.Properties  2
		$a_80_3 = {55 6e 69 6e 73 74 2e 65 78 65 } //Uninst.exe  -100
		$a_80_4 = {55 6e 69 6e 73 74 61 6c 6c 65 72 2e 65 78 65 } //Uninstaller.exe  -100
		$a_80_5 = {55 6e 69 6e 73 74 61 6c 2e 65 78 65 } //Uninstal.exe  -100
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*-100+(#a_80_4  & 1)*-100+(#a_80_5  & 1)*-100) >=6
 
}