package br.com.lnsoft.cryptography;

import java.io.File;
import java.nio.file.Files;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.OptionGroup;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

public class SteganographyCLI {

	public static void main(final String[] args) {
		SteganographyCLI steganography = new SteganographyCLI();
		try {
			steganography.initCLI(args);
			steganography.run();
		} catch (Exception e) {
			System.err.println(e.getLocalizedMessage());
			steganography.showHelp();
			System.exit(-1);
		}
	}

	public SteganographyCLI() {
		steganography = new Steganography();
	}

	private Steganography steganography;

	private enum Mode {
		ENCODE, DECODE
	}

	private static final String HELP = "h";
	private static final String HELP_LONG = "help";

	private static final String ENCODE_MODE = "ae";
	private static final String ENCODE_MODE_LONG = "encode";
	private static final String DECODE_MODE = "ad";
	private static final String DECODE_MODE_LONG = "decode";

	private static final String IMAGE_IN = "ii";
	private static final String IMAGE_IN_LONG = "image_in";
	private static final String IMAGE_OUT = "io";
	private static final String IMAGE_OUT_LONG = "image_out";

	private static final String DATA_IN = "di";
	private static final String DATA_IN_LONG = "data_in";
	private static final String DATA_OUT = "do";
	private static final String DATA_OUT_LONG = "data_out";

	private static final String MESSAGE_IN = "mi";
	private static final String MESSAGE_IN_LONG = "message_in";
	private static final String MESSAGE_OUT = "mo";
	private static final String MESSAGE_OUT_LONG = "message_out";

	private static final String FORCE = "f";
	private static final String FORCE_LONG = "force";

	private static final String OVERRIDE = "o";
	private static final String OVERRIDE_LONG = "override";

	private static final String SEED_VALUE = "sv";
	private static final String SEED_VALUE_LONG = "seed_value";
	private static final String SEED_STRING = "ss";
	private static final String SEED_STRING_LONG = "seed_string";

	private Options options;
	private CommandLine cmd;

	private void initCLI(final String[] args) throws ParseException {
		options = new Options();
		// command line options definition
		options.addOption(Option.builder(HELP).longOpt(HELP_LONG).desc("show this help message").build());
		// mode group
		OptionGroup modeGroup = new OptionGroup();
		modeGroup.addOption(
				Option.builder(ENCODE_MODE).longOpt(ENCODE_MODE_LONG).desc("set execution mode to 'encode'").build());
		modeGroup.addOption(
				Option.builder(DECODE_MODE).longOpt(DECODE_MODE_LONG).desc("set execution mode to 'decode'").build());
		options.addOptionGroup(modeGroup);
		// images
		options.addOption(Option.builder(IMAGE_IN).longOpt(IMAGE_IN_LONG).hasArg(true)
				.desc("set input image file path [REQUIRED]").build());
		options.addOption(Option.builder(IMAGE_OUT).longOpt(IMAGE_OUT_LONG).hasArg(true)
				.desc("set output image file path [REQUIRED only for 'encode' mode]").build());
		// force
		options.addOption(Option.builder(FORCE).longOpt(FORCE_LONG).desc("set force flag to use input image").build());
		// override
		options.addOption(Option.builder(OVERRIDE).longOpt(OVERRIDE_LONG)
				.desc("set override flag to overwrite exiting files").build());
		// encode type group
		OptionGroup encodeTypeInGroup = new OptionGroup();
		encodeTypeInGroup.addOption(
				Option.builder(DATA_IN).longOpt(DATA_IN_LONG).hasArg(true).desc("set input data file path").build());
		encodeTypeInGroup.addOption(Option.builder(MESSAGE_IN).longOpt(MESSAGE_IN_LONG).hasArg(true)
				.desc("set input message string").build());
		options.addOptionGroup(encodeTypeInGroup);
		// decode type group
		OptionGroup encodeTypeOutGroup = new OptionGroup();
		encodeTypeOutGroup.addOption(
				Option.builder(DATA_OUT).longOpt(DATA_OUT_LONG).hasArg(true).desc("set output data file path").build());
		encodeTypeOutGroup.addOption(Option.builder(MESSAGE_OUT).longOpt(MESSAGE_OUT_LONG).hasArg(false)
				.desc("set output to message string").build());
		options.addOptionGroup(encodeTypeOutGroup);
		// seed group
		OptionGroup seedGroup = new OptionGroup();
		seedGroup.addOption(Option.builder(SEED_VALUE).longOpt(SEED_VALUE_LONG).hasArg(true)
				.desc("set seed value: must be a number value").build());
		seedGroup.addOption(
				Option.builder(SEED_STRING).longOpt(SEED_STRING_LONG).hasArg(true).desc("set seed string").build());
		options.addOptionGroup(seedGroup);
		// parsing arguments
		CommandLineParser parser = new DefaultParser();
		cmd = parser.parse(options, args);
	}

	private void run() throws Exception {
		// show help
		if (cmd.hasOption(HELP)) {
			showHelp();
			return;
		}
		// mode
		Mode operationMode = getRequiredMode();
		// File Input
		File fileInput = getRequiredFileInput();
		// Seed
		setOptionalSeed();
		// mode options
		if (operationMode == Mode.ENCODE) {
			runEncode(fileInput);
		} else if (operationMode == Mode.DECODE) {
			runDecode(fileInput);
		}
	}

	private void runEncode(final File fileInput) throws Exception {
		// encode options
		if (!cmd.hasOption(IMAGE_OUT)) {
			throw new Exception("Missing required option: 'image_out' for 'encode' mode");
		}
		// Set inputData
		if (!cmd.hasOption(DATA_IN) && !cmd.hasOption(MESSAGE_IN)) {
			throw new Exception("Set one type of input: 'data_in' or 'message_in'");
		}
		// File Output
		File fileOutput;
		String outputFilenameValue = cmd.getOptionValue(IMAGE_OUT);
		fileOutput = new File(outputFilenameValue);
		if (fileOutput.exists() && !cmd.hasOption(OVERRIDE)) {
			throw new Exception(String.format("Output image file (%s) already exist. Set override flag to overwrite",
					fileOutput.getName()));
		}
		// in type
		byte[] inputData;
		if (cmd.hasOption(DATA_IN)) {
			String inputDataFilenameValue = cmd.getOptionValue(DATA_IN);
			File fileDataInput = new File(inputDataFilenameValue);
			if (!fileDataInput.exists()) {
				throw new Exception(String.format("Input image file (%s) not found", fileDataInput.getName()));
			}
			inputData = Files.readAllBytes(fileDataInput.toPath());
		} else if (cmd.hasOption(MESSAGE_IN)) {
			String optionMessageInValue = cmd.getOptionValue(MESSAGE_IN);
			inputData = optionMessageInValue.getBytes();
		} else {
			throw new Exception("Input must be 'data_in' or 'message_in'");
		}
		// load bitmap file
		byte[] image = Files.readAllBytes(fileInput.toPath());
		// encode Data
		byte[] encodeData = steganography.encodeData(image, inputData, cmd.hasOption(FORCE));
		// save image
		if (fileOutput.exists() && !cmd.hasOption(OVERRIDE)) {
			throw new Exception(String.format("Output image file (%s) already exist. Set override flag to overwrite",
					fileOutput.getName()));
		}
		Files.write(fileOutput.toPath(), encodeData);
		// show seed if not defined previously
		if ((!cmd.hasOption(SEED_VALUE) && !cmd.hasOption(SEED_STRING))) {
			System.out.println(String.format("Data inserted with %d seed", steganography.getSeed()));
		}
	}

	private void runDecode(final File fileInput) throws Exception {
		// decode options
		if (!cmd.hasOption(DATA_OUT) && !cmd.hasOption(MESSAGE_OUT)) {
			throw new Exception("Set one type of output: 'data_out' or 'message_out'");
		}
		File fileOutput = null;
		if (cmd.hasOption(DATA_OUT)) {
			// Data file Output
			String outputDataFilenameValue = cmd.getOptionValue(DATA_OUT);
			fileOutput = new File(outputDataFilenameValue);
			if (fileOutput.exists() && !cmd.hasOption(OVERRIDE)) {
				throw new Exception(String.format("Output data file (%s) already exist. Set override flag to overwrite",
						fileOutput.getName()));
			}
		}
		// load bitmap file
		byte[] image = Files.readAllBytes(fileInput.toPath());
		// decode Data
		byte[] decodeData = steganography.decodeData(image);
		// process decode data
		if (cmd.hasOption(MESSAGE_OUT)) {
			// output decoded message data
			System.out.println(String.format("Message data:\n%s", new String(decodeData)));
		} else if (cmd.hasOption(DATA_OUT)) {
			// save decoded data file
			Files.write(fileOutput.toPath(), decodeData);
		}
	}

	// show help
	private void showHelp() {
		// automatically generate the help statement
		HelpFormatter formatter = new HelpFormatter();
		formatter.setWidth(120);
		formatter.printHelp("Steganography", options);
	}

	private Mode getRequiredMode() throws Exception {
		Mode operationMode;
		// Mode validation
		if (cmd.hasOption(ENCODE_MODE)) {
			operationMode = Mode.ENCODE;
		} else if (cmd.hasOption(DECODE_MODE)) {
			operationMode = Mode.DECODE;
		} else {
			throw new Exception("Mode must be 'encode' or 'decode'");
		}
		//
		return operationMode;
	}

	private File getRequiredFileInput() throws Exception {
		File fileInput;
		// File Input
		String inputFilenameValue = cmd.getOptionValue(IMAGE_IN);
		fileInput = new File(inputFilenameValue);
		if (!fileInput.exists()) {
			throw new Exception(String.format("Input image file (%s) not found", fileInput.getName()));
		}
		//
		return fileInput;
	}

	private void setOptionalSeed() throws Exception {
		// Seed
		if (cmd.hasOption(SEED_STRING)) {
			String optionSeedStringValue = cmd.getOptionValue(SEED_STRING);
			// seed = computeSeedString(optionSeedStringValue);
			steganography.setSeed(optionSeedStringValue);
		} else if (cmd.hasOption(SEED_VALUE)) {
			String optionSeedValue = cmd.getOptionValue(SEED_VALUE);
			try {
				// seed = Long.parseLong(optionSeedValue);
				steganography.setSeed(Long.parseLong(optionSeedValue));
			} catch (NumberFormatException nfe) {
				throw new Exception(
						String.format("Number format exception: '%s' is not a valid number", optionSeedValue));
			}
		}
	}

}
