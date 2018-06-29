package br.com.lnsoft.cryptography.test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.io.File;
import java.nio.file.Files;

import org.junit.jupiter.api.Test;

import br.com.lnsoft.cryptography.Steganography;

public class BaseTests {

	private static final String INPUT_IMAGE = "fsociety.bmp";
	private static final String OUTPUT_IMAGE = "fsociety_out.bmp";
	private static final String INPUT_DATA = "mr_robot.jpg";

	@Test
	void test1() {
		long seed = 0;
		byte[] originalData = null;
		try {
			originalData = Files.readAllBytes(new File(INPUT_DATA).toPath());
			byte[] originalImage = Files.readAllBytes(new File(INPUT_IMAGE).toPath());
			//
			Steganography steganoEncode = new Steganography();
			// steganoEncode.setSeed(OFFSET_SEED);
			byte[] outputEncodeData = steganoEncode.encodeData(originalImage, originalData, false);
			Files.write(new File(OUTPUT_IMAGE).toPath(), outputEncodeData);
			//
			seed = steganoEncode.getSeed();
			System.out.println("Seed: " + seed);
		} catch (Exception e) {
			e.printStackTrace();
		}

		byte[] outputDecodeData = null;
		try {
			Steganography steganoDecode = new Steganography();
			// steganoDecode.setSeed(OFFSET_SEED);
			steganoDecode.setSeed(seed);
			byte[] encodedImage = Files.readAllBytes(new File(OUTPUT_IMAGE).toPath());
			outputDecodeData = steganoDecode.decodeData(encodedImage);
		} catch (Exception e) {
			e.printStackTrace();
		}

		assertArrayEquals(originalData, outputDecodeData);
	}

}
