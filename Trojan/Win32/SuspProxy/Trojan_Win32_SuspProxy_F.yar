
rule Trojan_Win32_SuspProxy_F{
	meta:
		description = "Trojan:Win32/SuspProxy.F,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_80_0 = {77 6c 72 6d 64 72 2e 65 78 65 20 } //wlrmdr.exe   1
		$a_80_1 = {2d 73 20 30 20 2d 66 20 30 20 2d 74 20 30 20 2d 6d 20 30 20 2d 61 20 31 31 20 2d 75 } //-s 0 -f 0 -t 0 -m 0 -a 11 -u  1
		$a_00_2 = {36 00 39 00 38 00 30 00 32 00 63 00 39 00 38 00 2d 00 32 00 63 00 65 00 32 00 2d 00 34 00 61 00 31 00 37 00 2d 00 39 00 38 00 70 00 30 00 2d 00 33 00 61 00 39 00 32 00 32 00 30 00 61 00 64 00 30 00 31 00 35 00 37 00 } //-1 69802c98-2ce2-4a17-98p0-3a9220ad0157
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_00_2  & 1)*-1) >=2
 
}
rule Trojan_Win32_SuspProxy_F_2{
	meta:
		description = "Trojan:Win32/SuspProxy.F,SIGNATURE_TYPE_CMDHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_80_0 = {63 6d 64 2e 65 78 65 20 2f 63 } //cmd.exe /c  1
		$a_80_1 = {74 69 6d 65 6f 75 74 } //timeout  1
		$a_80_2 = {74 61 73 6b 6c 69 73 74 20 2f 73 76 63 } //tasklist /svc  1
		$a_80_3 = {66 69 6e 64 73 74 72 20 2f 69 } //findstr /i  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=2
 
}