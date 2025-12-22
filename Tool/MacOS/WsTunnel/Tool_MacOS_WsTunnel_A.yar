
rule Tool_MacOS_WsTunnel_A{
	meta:
		description = "Tool:MacOS/WsTunnel.A,SIGNATURE_TYPE_MACHOHSTR_EXT,3c 00 3c 00 07 00 00 "
		
	strings :
		$a_00_0 = {77 73 54 75 6e 6e 65 6c 43 6c 69 65 6e 74 } //10 wsTunnelClient
		$a_00_1 = {77 73 54 75 6e 6e 65 6c 53 65 72 76 65 72 } //10 wsTunnelServer
		$a_00_2 = {72 65 76 65 72 73 65 20 74 75 6e 6e 65 6c } //10 reverse tunnel
		$a_00_3 = {48 61 6e 64 73 68 61 6b 65 50 61 79 6c 6f 61 64 } //10 HandshakePayload
		$a_00_4 = {55 53 45 52 3a 50 41 53 53 40 48 4f 53 54 3a 50 4f 52 54 } //10 USER:PASS@HOST:PORT
		$a_00_5 = {48 54 54 50 5f 55 50 47 52 41 44 45 5f 50 41 54 48 5f 50 52 45 46 49 58 } //10 HTTP_UPGRADE_PATH_PREFIX
		$a_00_6 = {68 69 63 6b 6f 72 79 2d 70 72 6f 74 6f } //10 hickory-proto
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*10+(#a_00_6  & 1)*10) >=60
 
}