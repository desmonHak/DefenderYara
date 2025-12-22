
rule _#PUA_Block_RDPWrap{
	meta:
		description = "!#PUA:Block:RDPWrap,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_80_0 = {52 44 50 57 49 6e 73 74 2e 65 78 65 20 5b 2d 6c 7c 2d 69 5b 2d 73 5d 7c 2d 77 7c 2d 75 7c 2d 72 5d } //RDPWInst.exe [-l|-i[-s]|-w|-u|-r]  1
		$a_80_1 = {72 64 70 77 72 61 70 2e 69 6e 69 } //rdpwrap.ini  1
		$a_80_2 = {52 44 50 20 57 72 61 70 70 65 72 20 4c 69 62 72 61 72 79 } //RDP Wrapper Library  1
		$a_80_3 = {52 44 50 20 57 72 61 70 70 65 72 20 55 70 64 61 74 65 } //RDP Wrapper Update  1
		$a_80_4 = {25 50 72 6f 67 72 61 6d 46 69 6c 65 73 25 5c 52 44 50 20 57 72 61 70 70 65 72 } //%ProgramFiles%\RDP Wrapper  1
		$a_80_5 = {52 44 50 57 49 6e 73 74 2e 65 78 65 20 5b 2d 6c 7c 2d 69 5b 2d 73 5d 5b 2d 6f 5d 7c 2d 77 7c 2d 75 5b 2d 6b 5d 7c 2d 72 5d } //RDPWInst.exe [-l|-i[-s][-o]|-w|-u[-k]|-r]  1
		$a_80_6 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 73 79 73 74 65 6d 33 32 5c 72 64 70 } //%SystemRoot%\system32\rdp  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1) >=4
 
}