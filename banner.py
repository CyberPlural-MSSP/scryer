END = '\001\033[0m\002'


def print_banner():
	print('\r')
	padding = '  '

	S = [
		'███████╗',
		'██╔════╝',
		'███████╗',
		'╚════██║',
		'███████║',
		'╚══════╝'
	]

	C = [
		' ██████╗',
		'██╔════╝',
		'██║     ',
		'██║     ',
		'╚██████╗',
		' ╚═════╝'
	]

	R = [
		'██████╗ ',
		'██╔══██╗',
		'██████╔╝',
		'██╔══██╗',
		'██║  ██║',
		'╚═╝  ╚═╝'
	]

	Y = [
		'██╗   ██╗',
		'╚██╗ ██╔╝',
		' ╚████╔╝ ',
		'  ╚██╔╝  ',
		'   ██║   ',
		'   ╚═╝   '
	]

	E = [
		'███████╗',
		'██╔════╝',
		'█████╗  ',
		'██╔══╝  ',
		'███████╗',
		'╚══════╝'
	]

	banner = [S, C, R, Y, E, R]
	final = []	
	init_color = 89

	txt_color = init_color
	cl = 0
		
	for charset in range(0, 6):
		for pos in range(0, len(banner)):
			for i in range(0, len(banner[pos][charset])):
				clr = f'\033[38;5;{txt_color}m'
				char = f'{clr}{banner[pos][charset][i]}'
				final.append(char)
				cl += 1
				txt_color = txt_color + 1 if cl <= 3 else txt_color

			cl = 0

			txt_color = init_color
		
		if init_color % 3 == 1:
			init_color += 1

		if charset < 5: final.append('\n   ')

	print(f"   {''.join(final)}")
	print(f'{END}')

if __name__ == '__main__':
	print_banner()