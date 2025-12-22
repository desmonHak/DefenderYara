
rule _#PUA_Block_AdGazelle{
	meta:
		description = "!#PUA:Block:AdGazelle,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {41 64 47 61 7a 65 6c 6c 65 } //AdGazelle  2
		$a_80_1 = {73 68 6f 77 5f 65 75 6c 61 5f 6f 66 66 65 72 } //show_eula_offer  1
		$a_80_2 = {74 68 69 72 64 20 70 61 72 74 79 } //third party  1
		$a_80_3 = {61 64 67 61 7a 65 6c 6c 65 2e 63 6f 6d } //adgazelle.com  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_AdGazelle_2{
	meta:
		description = "!#PUA:Block:AdGazelle,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_80_0 = {66 75 67 67 64 6f 77 6e 6c 6f 61 64 73 31 30 32 2e 63 6f 6d } //fuggdownloads102.com  2
		$a_80_1 = {57 72 61 70 70 65 72 58 74 72 61 4c 49 54 45 2e 70 64 62 } //WrapperXtraLITE.pdb  1
		$a_80_2 = {61 64 73 31 30 32 2e 63 6f 6d } //ads102.com  1
		$a_80_3 = {73 65 74 75 70 2e 65 6e 63 } //setup.enc  1
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=5
 
}
rule _#PUA_Block_AdGazelle_3{
	meta:
		description = "!#PUA:Block:AdGazelle,SIGNATURE_TYPE_PEHSTR,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {70 6f 70 61 6a 61 72 33 5c 53 44 4b 4f 62 66 75 73 63 61 74 69 6f 6e 5c 4f 62 66 75 73 63 61 74 6f 72 5c 57 72 61 70 70 65 72 58 74 72 61 4c 49 54 45 5c 57 72 61 70 70 65 72 58 74 72 61 4c 49 54 45 2e 70 64 62 } //2 popajar3\SDKObfuscation\Obfuscator\WrapperXtraLITE\WrapperXtraLITE.pdb
		$a_01_1 = {67 65 74 6f 66 66 65 72 73 2e 76 61 6c 69 64 61 74 65 64 69 6e 73 74 61 6c 6c 61 74 69 6f 6e 2e 63 6f 6d } //1 getoffers.validatedinstallation.com
		$a_01_2 = {41 64 47 61 7a 65 6c 6c 65 } //1 AdGazelle
		$a_01_3 = {41 47 49 6e 73 74 61 6c 6c 65 72 4c 69 62 72 61 72 79 } //1 AGInstallerLibrary
		$a_01_4 = {2d 2d 69 6e 73 74 61 6c 6c 2d 66 72 6f 6d 2d 77 65 62 73 74 6f 72 65 3d } //1 --install-from-webstore=
		$a_01_5 = {70 6f 70 61 6a 61 72 33 5c 49 6e 73 74 61 6c 6c 65 72 73 5c 56 61 6c 69 64 61 74 69 6f 6e 53 63 72 69 70 74 4c 69 62 72 61 72 79 2e 70 64 62 } //1 popajar3\Installers\ValidationScriptLibrary.pdb
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=2
 
}