
rule HackTool_Win32_Keygen_AMTB{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 79 67 65 6e 6e 65 64 20 62 79 } //2 Keygenned by
		$a_01_1 = {46 46 46 4b 45 59 47 45 4e } //2 FFFKEYGEN
		$a_01_2 = {46 69 47 48 54 69 4e 47 20 46 4f 52 20 46 55 4e 20 50 52 45 53 45 4e 54 53 } //1 FiGHTiNG FOR FUN PRESENTS
		$a_01_3 = {53 65 56 65 4e 20 2f 20 46 46 46 } //1 SeVeN / FFF
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_AMTB_2{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_80_0 = {2a 4b 65 79 6d 61 6b 65 72 2a 20 62 79 20 54 65 61 6d 20 43 61 66 65 } //*Keymaker* by Team Cafe  2
		$a_80_1 = {4b 65 79 6d 61 6b 65 72 20 62 79 20 54 65 61 6d 20 43 61 66 65 } //Keymaker by Team Cafe  2
		$a_01_2 = {48 69 74 20 74 68 65 20 67 65 6e 65 72 61 74 65 20 62 75 74 74 6f 6e } //1 Hit the generate button
		$a_01_3 = {47 65 6e 65 72 61 74 65 } //1 Generate
		$a_80_4 = {53 65 72 69 61 6c 3a } //Serial:  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_80_4  & 1)*1) >=4
 
}
rule HackTool_Win32_Keygen_AMTB_3{
	meta:
		description = "HackTool:Win32/Keygen!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a 20 6e 2d 67 65 6e 23 30 31 [0-0f] 46 61 73 74 54 72 61 63 6b 65 72 20 76 32 2e 30 30 } //1
		$a_03_1 = {43 72 61 63 6b 65 72 20 3a 20 4e 2d 47 65 6e [0-04] 50 72 6f 74 65 63 74 69 6f 6e 20 3a 20 43 72 61 70 70 79 20 56 42 20 21 21 21 [0-04] 54 68 6b 73 20 3a 20 4e 2d 47 65 6e 20 63 72 65 77 20 3b 29 [0-04] 4d 41 59 20 54 48 45 20 4c 55 4d 49 4e 4f 55 20 42 45 20 57 49 54 48 20 59 4f 55 20 21 21 [0-96] 45 78 74 65 6e 64 65 64 20 4d 6f 64 75 6c 65 3a } //1
		$a_03_2 = {56 65 72 73 69 6f 6e 20 4d 6f 6e 6f 70 6f 73 74 65 [0-05] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-0a] 50 6f 73 74 65 73 [0-05] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-0a] 50 6f 73 74 65 73 [0-05] 56 65 72 73 69 6f 6e 20 52 65 73 65 61 75 [0-0a] 50 6f 73 74 65 73 } //1
		$a_01_3 = {2d 2d 2d 2d 2d 2d 2d 77 77 77 2e 63 65 72 72 6f 72 2e 74 6b 2d 2d } //1 -------www.cerror.tk--
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}