# Steganography

From [Wikipedia](https://en.wikipedia.org/wiki/Steganography), **Steganography** is the practice of concealing a file, message, image, or video within another file, message, image, or video. The word steganography combines the Greek words steganos, meaning "covered, concealed, or protected", and graphein meaning "writing".

#Bitmap

This implementation only restrict the target file to bitmaps images because it is usually a large file with a small header footprint.

A bitmap image is comprised of pixels in a matrix. Each pixel in the image contains information about the color to be displayed.

Each pixel is encoded with the basic three colors - Red, Green, Blue - with one byte per color.

Changing the least significants bits (LSB) of each pixel have a very little impact in the bitmap image.

We use only the two LSB of each color bit of the bitmap image to encode the data file.

To encode one byte of data we use four bytes of the bitmap image.

# Maven 

Run Maven *install* to create the artifacts. Maven will create the runnable jar named *"steganography-1.0.0-SNAPSHOT-jar-with-dependencies.jar"* to simplify I will name it just *"steganoCLI.jar"*.

Run it as a Jar file with this command line:

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

# Encode

To **encode** (first argument '-ae') a data file within a bitmap image use this command line:

	>java -jar steganoCLI.jar -ae -ii fsociety.bmp -io fsociety_out.bmp -di mr_robot.jpg -ss secret_seed

The '-ii' argument will specify the bitmap "image input" and the '-io' the bitmap "image output".

The '-di' argument is the "data input" in this case a JPEG image and the '-ss' define a "seed string".

# Decode

To **decode** (first argument '-ad') the data file from the encoded bitmap file use this command line:

	>java -jar steganoCLI.jar -ad -ii fsociety_out.bmp -do mr_robot.jpg -ss secret_seed

The '-ii' argument will specify the bitmap "image input" with the concealed data.

The '-do' argument is the "data output" in this case the data within the bitmap and the '-ss' must be the same "seed string" used in the encoding process.

# Parameters

Use '-f' force parameter to use a bitmap image where a steganography signature was already detected.

Use '-o' override parameter to override an existing output file.

# Seed

The seed parameter is optional and it will be used to compute the offset index in the bitmap where the data input will be concealed.

You always need to provide the same seed used in the encode process to successfully decode the data concealed.

When the seed parameter is not provided a random seed will be used and shown in the output console after data is concealed. This seed must be noted to be use in the decode process.

If either the '-ss' "seed string" or '-sv' "seed value" is provided in the encode process it must be provide exactly the same type and value in the decode process to retrieve the data concealed.
