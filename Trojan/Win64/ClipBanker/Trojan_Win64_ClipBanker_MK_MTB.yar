
rule Trojan_Win64_ClipBanker_MK_MTB{
	meta:
		description = "Trojan:Win64/ClipBanker.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f 57 c9 66 0f 7f 8d ?? ?? ?? 00 4c 89 bd ?? ?? ?? 00 66 0f 7f 85 ?? ?? ?? 00 4c 8d 0d ?? 28 02 00 4c 8d 05 } //20
		$a_01_1 = {66 69 72 65 66 6f 78 2e 65 78 65 } //15 firefox.exe
		$a_01_2 = {62 72 6f 77 73 65 72 2e 64 6c 6c } //10 browser.dll
		$a_01_3 = {2d 2d 64 69 73 61 62 6c 65 2d 68 74 74 70 32 20 2d 2d 75 73 65 2d 73 70 64 79 3d 6f 66 66 20 2d 2d 64 69 73 61 62 6c 65 2d 71 75 69 63 } //5 --disable-http2 --use-spdy=off --disable-quic
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*15+(#a_01_2  & 1)*10+(#a_01_3  & 1)*5) >=50
 
}