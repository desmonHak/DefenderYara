
rule Trojan_Win32_SuspProxy_O{
	meta:
		description = "Trojan:Win32/SuspProxy.O,SIGNATURE_TYPE_CMDHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 20 73 65 74 78 } //cmd.exe /c setx  1
		$a_80_1 = {50 55 42 55 52 4c } //PUBURL  1
		$a_80_2 = {68 74 74 70 3a 2f 2f 70 63 73 64 6c 2e 63 6f 6d 2f 73 68 6f 72 74 2d 75 72 6c } //http://pcsdl.com/short-url  1
		$a_80_3 = {64 75 6d 6d 79 5f 65 6d 70 69 72 65 5f 61 67 65 6e 74 } //dummy_empire_agent  1
		$a_80_4 = {2e 70 73 31 20 2f 6d } //.ps1 /m  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=5
 
}