# Steganography

From [Wikipedia](https://en.wikipedia.org/wiki/Steganography), **Steganography** is the practice of concealing a file, message, image, or video within another file, message, image, or video. The word steganography combines the Greek words steganos, meaning "covered, concealed, or protected", and graphein meaning "writing". 

In this implementation I will only restrict the target file to bitmaps images cause it is a large file with a small header fingerprint.

Just run Maven install to create the artifacts.

Maven will create the runnable jar with this name:

"steganography-1.0.0-SNAPSHOT-jar-with-dependencies.jar"

To simplify name it to steganoCLI.jar

Run as a Jar file with this command line:

	>java -jar steganoCLI.jar
	Mode must be 'encode' or 'decode'
	usage: Steganography
	 -ad,--decode              set execution mode to 'decode'
	 -ae,--encode              set execution mode to 'encode'
	 -di,--data_in <arg>       set input data file path
	 -do,--data_out <arg>      set output data file path
	 -f,--force                set force flag to use input image
	 -h,--help                 show this help message
	 -ii,--image_in <arg>      set input image file path [REQUIRED]
	 -io,--image_out <arg>     set output image file path [REQUIRED only for 'encode' mode]
	 -mi,--message_in <arg>    set input message string
	 -mo,--message_out         set output to message string
	 -o,--override             set override flag to overwrite exiting files
	 -ss,--seed_string <arg>   set seed string
	 -sv,--seed_value <arg>    set seed value: must be a number value

To encode (first argument -ae) a data file within a bitmap image use this command line:

	>java -jar steganoCLI.jar -ae -ii fsociety.bmp -io fsociety_out.bmp -di mr_robot.jpg -ss secret_seed

The -ii argument will specify the bitmap "image input" and the -io the bitmap "image output"

The -di argument is the "data input" in this case a JPEG image and the -ss define a "seed string"

To decode (first argument -ad) the data file from the encoded bitmap file use this command line:

	>java -jar steganoCLI.jar -ad -ii fsociety_out.bmp -do mr_robot.jpg -ss secret_seed

