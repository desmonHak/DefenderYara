
rule HackTool_Win32_Greedy_AMTB{
	meta:
		description = "HackTool:Win32/Greedy!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_80_0 = {44 75 6d 70 } //Dump  1
		$a_80_1 = {50 6f 72 74 } //Port  1
		$a_80_2 = {6d 61 69 6e 2e 28 2a 41 75 74 6f 49 6e 6a 65 63 74 6f 72 29 2e 63 72 65 61 74 65 50 61 79 6c 6f 61 64 44 4c 4c } //main.(*AutoInjector).createPayloadDLL  2
		$a_80_3 = {6d 61 69 6e 2e 73 63 61 6e 42 72 6f 77 73 65 72 44 61 74 61 } //main.scanBrowserData  2
		$a_80_4 = {6d 61 69 6e 2e 65 78 66 69 6c 74 72 61 74 65 52 65 73 75 6c 74 73 } //main.exfiltrateResults  2
		$a_80_5 = {67 69 74 68 75 62 2e 63 6f 6d 2f 6d 6f 6f 6e 64 34 72 6b 2f 68 61 63 6b 62 72 6f 77 73 65 72 64 61 74 61 } //github.com/moond4rk/hackbrowserdata  4
		$a_02_6 = {50 00 61 00 73 00 73 00 77 00 6f 00 72 00 64 00 [0-10] 42 00 6f 00 6f 00 6b 00 6d 00 61 00 72 00 6b 00 [0-10] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 } //4
		$a_02_7 = {50 61 73 73 77 6f 72 64 [0-10] 42 6f 6f 6b 6d 61 72 6b [0-10] 44 6f 77 6e 6c 6f 61 64 } //4
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*2+(#a_80_3  & 1)*2+(#a_80_4  & 1)*2+(#a_80_5  & 1)*4+(#a_02_6  & 1)*4+(#a_02_7  & 1)*4) >=16
 
}