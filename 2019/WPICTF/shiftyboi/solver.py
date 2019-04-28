import binascii

def clk(time):
	output = ""
	registers = [1, 1, 1, 1, 1, 1]
	for t in range(time):
		newregisters = [0, 0, 0, 0, 0, 0]
		newregisters[0] = registers[1]
		newregisters[1] = registers[2]
		newregisters[2] = registers[3]
		newregisters[3] = registers[4]
		newregisters[4] = registers[5]
		newregisters[5] = (registers[4] + registers[1]) % 2
		output += str(registers[0])
		for i in range(6):
			registers[i] = newregisters[i]
	return output

def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))

hint = "10111100000111000101011000000110101010111011010101100001101000001110001010001011010101011110110101110100110111010010111101100000"
output = clk(8*16)
flag_int = int(hint, 2) ^ int(output[::-1], 2)

print int2bytes(flag_int).decode('utf-8')
