import argparse
import os
import sys
import acllib

def get_options(cmd_args=None):
	cmd_parser = argparse.ArgumentParser(
		formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	
	cmd_parser.add_argument(
		'-i',
		'--input_file',
		help="""filename of the IOS ACL to translate""",
		type=str,
		default='')

	cmd_parser.add_argument(
		'-if',
		'--input_format',
		help="""format of the input file (ios,nxs)""",
		type=str,
		default='ios')

	cmd_parser.add_argument(
		'-of',
		'--output_format',
		help="""format of the output file (ios,nxs)""",
		type=str,
		default='nxs')

	args = cmd_parser.parse_args(cmd_args)

	options = {}
	options['input_file'] = args.input_file
	options['input_format'] = args.input_format
	options['output_format'] = args.output_format

	return options



def main(options):
	input_filepath = options['input_file']
	filename = os.path.basename(input_filepath)
	
	output_filename = filename + "." + options['output_format']
	error_filename	= filename + "." + options['output_format'] + ".errors"

	print("# translating {}".format(input_filepath))
	print("# from: {} syntax".format(options['input_format']))
	print("# to: {} syntax".format(options['output_format']))

	acl 	= acllib.parseACLFile(input_filepath,options['input_format'])	

	(translated_lines,problematic_lines) = acllib.ACL2Text(acl,options['output_format'])
	
	# write translation file
	with open(output_filename,"w") as good:
		good.write("\n".join(translated_lines))
		print("# wrote translation to: {}".format(output_filename))

	# write error file
	with open(error_filename,"w") as error:
		for pl in problematic_lines:
			error.write(str(pl) + "\n")
		print("# noted {} errors to: {}".format(len(problematic_lines),error_filename))

if __name__ == "__main__":
	sys.exit(main(get_options()))
