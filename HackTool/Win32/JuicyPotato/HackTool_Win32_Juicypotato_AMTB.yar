
rule HackTool_Win32_Juicypotato_AMTB{
	meta:
		description = "HackTool:Win32/Juicypotato!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {53 77 65 65 74 50 6f 74 61 74 6f 2e 65 78 65 } //SweetPotato.exe  2
		$a_80_1 = {53 77 65 65 74 50 6f 74 61 74 6f 2e 70 64 62 } //SweetPotato.pdb  2
		$a_80_2 = {70 72 69 6e 74 53 70 6f 6f 66 65 72 } //printSpoofer  2
		$a_80_3 = {50 6f 74 61 74 6f 41 50 49 } //PotatoAPI  2
		$a_80_4 = {77 69 6e 52 4d 4c 69 73 74 65 6e 65 72 } //winRMListener  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*1) >=5
 
}