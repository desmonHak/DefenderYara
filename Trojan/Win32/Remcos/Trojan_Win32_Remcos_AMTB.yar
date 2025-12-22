
rule Trojan_Win32_Remcos_AMTB{
	meta:
		description = "Trojan:Win32/Remcos!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 0c 00 00 "
		
	strings :
		$a_80_0 = {6b 65 72 6e 73 78 63 65 6c 33 32 } //kernsxcel32  1
		$a_80_1 = {6b 65 78 63 73 72 6e 65 6c 33 32 } //kexcsrnel32  1
		$a_80_2 = {6b 65 72 78 63 6e 73 65 6c 33 32 } //kerxcnsel32  1
		$a_80_3 = {6b 65 72 73 6e 78 63 65 6c 33 32 } //kersnxcel32  1
		$a_80_4 = {6b 73 78 63 65 72 6e 65 6c 33 32 } //ksxcernel32  1
		$a_80_5 = {6b 65 72 44 78 63 6e 65 6c 33 32 } //kerDxcnel32  1
		$a_80_6 = {6b 65 72 6e 78 63 44 65 6c 33 32 } //kernxcDel32  1
		$a_80_7 = {6b 65 78 63 72 44 6e 65 6c 33 32 } //kexcrDnel32  1
		$a_80_8 = {6b 65 72 6e 65 44 6c 78 63 33 32 } //kerneDlxc32  1
		$a_80_9 = {6b 65 44 72 78 63 6e 65 6c 33 32 } //keDrxcnel32  1
		$a_80_10 = {73 68 78 63 65 44 6c 6c 33 32 2e 64 6c 6c } //shxceDll32.dll  1
		$a_80_11 = {6b 65 44 78 63 72 6e 65 6c 33 32 } //keDxcrnel32  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1+(#a_80_6  & 1)*1+(#a_80_7  & 1)*1+(#a_80_8  & 1)*1+(#a_80_9  & 1)*1+(#a_80_10  & 1)*1+(#a_80_11  & 1)*1) >=12
 
}