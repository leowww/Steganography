package br.com.lnsoft.cryptography;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Random;

public class Steganography {

	private static final int COMPRESSION_FACTOR = 4;

	private static final int DIB_HEADER_OFFSET = 14;
	private static final int SIGNATURE_OFFSET = 6;

	private static final int LENGTH_HEADER_SIZE = 32 / COMPRESSION_FACTOR;
	private static final int OFFSET_HEADER_SIZE = 32 / COMPRESSION_FACTOR;
	private static final int HASH_HEADER_SIZE = 128 / COMPRESSION_FACTOR;

	private static final byte[] SIGNATURE = new byte[] { (byte) 0x4c, (byte) 0x4e, (byte) 0x76, (byte) 0x31 };

	private static final int INT_SIZE = 4;

	private long seed;

	public Steganography() {
		setSeed(null);
	}

	public long getSeed() {
		return seed;
	}

	public void setSeed(final String seedString) {
		seed = computeSeedString(seedString);
	}

	public void setSeed(final long seed) {
		this.seed = seed;
	}

	public byte[] encodeData(final byte[] image, final byte[] data, final boolean force) throws Exception {
		byte[] encodeData;
		// check first two bytes bitmap identification
		if (!(image[0] == 0x42 && image[1] == 0x4D)) {
			throw new IllegalArgumentException("Invalid file format. Only Bitmap file supported.");
		}
		// checks if SIGNATURE exists
		if (checkSignature(image) && !force) {
			throw new IllegalArgumentException(
					"Signature detected. Set force flag to use this image to encode data in. Previous data encoded will be lost.");
		}
		// add SIGNATURE
		setImageSignature(image);
		// compute base header offset
		int baseHeaderOffset = computeBaseHeaderOffset(image);
		// add data length
		encodeDataLength(image, baseHeaderOffset, data.length);
		// computeImageOffset
		int offset = computeImageOffset(baseHeaderOffset, image.length, data.length);
		// add data offset
		encodeDataOffset(image, baseHeaderOffset, offset);
		// add hash
		encodeDataHash(image, baseHeaderOffset, data);
		// encodeBytes
		encodeData = encodeDataBytes(image, offset, data);
		//
		return encodeData;
	}

	public byte[] decodeData(final byte[] image) throws Exception {
		byte[] decodeData;
		// check first two bytes bitmap identification
		if (!(image[0] == 0x42 && image[1] == 0x4D)) {
			throw new IllegalArgumentException("Invalid file format. Only Bitmap file supported.");
		}
		// checks if SIGNATURE is valid
		if (!checkSignature(image)) {
			throw new IllegalArgumentException("Decode error. Invalid signature");
		}
		// compute base header offset
		int baseHeaderOffset = computeBaseHeaderOffset(image);
		// retrieve length
		int dataLength = decodeDataLength(image, baseHeaderOffset);
		// computeImageOffset
		int offset = computeImageOffset(baseHeaderOffset, image.length, dataLength);
		// retrieve offset
		int dataOffset = decodeDataOffset(image, baseHeaderOffset);
		// check compute and retrieved data offset
		if (offset != dataOffset) {
			throw new IllegalArgumentException("Decode error. Invalid offset");
		}
		// retrieve hash
		byte[] hash = decodeDataHash(image, baseHeaderOffset);
		// decodeBytes
		decodeData = decodeDataBytes(image, offset, dataLength);
		// check hash
		if (!checkDataHash(decodeData, hash)) {
			throw new IllegalArgumentException("Decode error. Invalid hash");
		}
		//
		return decodeData;
	}

	//
	// Core data encode/decode
	//

	private byte[] encodeDataBytes(final byte[] image, final int initialOffset, final byte[] data) {
		// add data to image
		int offset = initialOffset;
		for (int i = 0; i < data.length; ++i) {
			image[offset] = (byte) ((image[offset] & 0xF0) | (((data[i] >>> 7) & 1) << 3));
			image[offset] = (byte) (image[offset] | (((data[i] >>> 6) & 1)) << 2);
			image[offset] = (byte) (image[offset] | (((data[i] >>> 5) & 1) << 1));
			image[offset] = (byte) (image[offset] | ((data[i] >>> 4) & 1));
			offset++;
			image[offset] = (byte) ((image[offset] & 0xF0) | (((data[i] >>> 3) & 1) << 3));
			image[offset] = (byte) (image[offset] | (((data[i] >>> 2) & 1)) << 2);
			image[offset] = (byte) (image[offset] | (((data[i] >>> 1) & 1) << 1));
			image[offset] = (byte) (image[offset] | ((data[i] >>> 0) & 1));
			offset++;
		}
		//
		return image;
	}

	private byte[] decodeDataBytes(final byte[] image, final int initialOffset, final int length) {
		// retrieve original data
		int offset = initialOffset;
		byte[] result = new byte[length];
		for (int b = 0; b < result.length; ++b) {
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 8) >> 3);
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 4) >> 2);
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 2) >> 1);
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 1));
			offset++;
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 8) >> 3);
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 4) >> 2);
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 2) >> 1);
			result[b] = (byte) ((result[b] << 1) | (image[offset] & 1));
			offset++;
		}
		// return result data
		return result;
	}

	//
	// Signature methods
	// Use the Unused 2 fields at BMP Header
	// 2 bytes at offset 6 and 2 bytes more at offset 8
	// add and retrieve a predefined signature
	//

	// encode
	private void setImageSignature(final byte[] image) {
		// add SIGNATURE
		for (int idx = 0; idx < SIGNATURE.length; idx++) {
			image[SIGNATURE_OFFSET + idx] = SIGNATURE[idx];
		}
	}

	// decode
	private byte[] getImageSignature(final byte[] image) {
		// retrieve SIGNATURE
		byte[] signature = new byte[SIGNATURE.length];
		for (int idx = 0; idx < SIGNATURE.length; idx++) {
			signature[idx] = image[SIGNATURE_OFFSET + idx];
		}
		// return decoded signature
		return signature;
	}

	// check
	private boolean checkSignature(final byte[] image) {
		// compare signatures
		return Arrays.equals(getImageSignature(image), SIGNATURE);
	}

	//
	// Length methods
	//

	// encode length
	private void encodeDataLength(final byte[] image, final int baseHeaderOffset, final int length) {
		// add data length
		encodeDataBytes(image, baseHeaderOffset, int2ByteArray(length));
	}

	// decode length
	private int decodeDataLength(final byte[] image, final int baseHeaderOffset) {
		int dataLength = 0;
		byte[] byteLength = decodeDataBytes(image, baseHeaderOffset, INT_SIZE);
		dataLength = byteArray2Int(byteLength);
		return dataLength;
	}

	//
	// Offset methods
	//

	// encode offset
	private void encodeDataOffset(final byte[] image, final int baseHeaderOffset, final int offset) {
		// add data offset
		encodeDataBytes(image, baseHeaderOffset + LENGTH_HEADER_SIZE, int2ByteArray(offset));
	}

	// decode offset
	private int decodeDataOffset(final byte[] image, final int baseHeaderOffset) {
		int dataOffset = 0;
		byte[] decodeDataBytes = decodeDataBytes(image, baseHeaderOffset + LENGTH_HEADER_SIZE, INT_SIZE);
		dataOffset = byteArray2Int(decodeDataBytes);
		return dataOffset;
	}

	private int computeBaseHeaderOffset(byte[] image) {
		// compute base offset
		int baseHeaderOffset = 0;
		int dibHeaderSize = 0;
		byte[] dibData = (new byte[] { image[DIB_HEADER_OFFSET + 3], image[DIB_HEADER_OFFSET + 2],
				image[DIB_HEADER_OFFSET + 1], image[DIB_HEADER_OFFSET] });
		for (int idx = 0; idx < INT_SIZE; idx++) {
			dibHeaderSize = (dibHeaderSize << 8) | (dibData[idx] & 0xFF);
		}
		baseHeaderOffset = DIB_HEADER_OFFSET + dibHeaderSize;
		// return baseHeaderOffset
		return baseHeaderOffset;
	}

	// compute offset
	// headerSize | valid data area
	// max offset consider original image length minus data length * <compression factor> (=8/bits per image byte)
	// minus total header size
	private int computeImageOffset(final int baseHeaderOffset, final int imageLength, final int dataLength) {
		int offset = 0;
		Random rand = new Random(seed);
		int headerSize = baseHeaderOffset + LENGTH_HEADER_SIZE + OFFSET_HEADER_SIZE + HASH_HEADER_SIZE;
		int compressionFactor = 8 / COMPRESSION_FACTOR;
		int maxOffset = imageLength - ((compressionFactor * dataLength) + headerSize);
		offset = rand.nextInt(maxOffset) + headerSize;
		if (offset < headerSize || offset > maxOffset) {
			throw new IllegalArgumentException(
					String.format("Invalid offset. Must be between %d and %d.", baseHeaderOffset, maxOffset));
		}
		return offset;
	}

	//
	// Hash
	//

	private void encodeDataHash(final byte[] image, final int baseHeaderOffset, final byte[] data) {
		encodeDataBytes(image, baseHeaderOffset + LENGTH_HEADER_SIZE + OFFSET_HEADER_SIZE, computeHash(data));
	}

	private byte[] decodeDataHash(final byte[] image, final int baseHeaderOffset) {
		byte[] hash = decodeDataBytes(image, baseHeaderOffset + LENGTH_HEADER_SIZE + OFFSET_HEADER_SIZE, 16);
		return hash;
	}

	private boolean checkDataHash(final byte[] decodeData, final byte[] hash) {
		return Arrays.equals(computeHash(decodeData), hash);
	}

	private byte[] computeHash(final byte[] data) {
		byte[] digest = null;
		try {
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			digest = md5.digest(data);
			// System.out.print("MD5: ");
			// for (byte c : digest) {
			// System.out.print(String.format("%02x", c));
			// }
			// System.out.println();
		} catch (NoSuchAlgorithmException e) {
		}
		return digest;
	}

	//
	// Seed
	//

	private long computeSeedString(final String seedString) {
		long computedSeed = 0;
		if (seedString == null || seedString.isEmpty()) {
			Random rand = new Random(Calendar.getInstance().getTimeInMillis());
			computedSeed = rand.nextLong();
		} else {
			try {
				MessageDigest md5 = MessageDigest.getInstance("MD5"); //$NON-NLS-1$
				byte[] digest = md5.digest(seedString.getBytes()); // 128 bits => 16 bytes
				int offset = digest[15] & 0x0F;
				for (int idx = 0; idx < 8; idx++) { // long 64 bits = 8 bytes
					long b = digest[(idx + offset) % 16] & 0xff;
					computedSeed = (computedSeed << 8) | b;
				}
			} catch (NoSuchAlgorithmException e) {
			}
		}
		return computedSeed;
	}

	//
	// byte[] <=> int conversions
	//

	// int to byte[]
	private byte[] int2ByteArray(final int data) {
		byte bytes[] = new byte[INT_SIZE];
		for (int idx = 0; idx < INT_SIZE; idx++) {
			bytes[idx] = (byte) ((data >> (idx * 8)) & 0xFF);
		}
		return (new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] });
	}

	// byte[] to int
	private int byteArray2Int(final byte[] data) {
		int value = 0;
		for (int idx = 0; idx < INT_SIZE; idx++) {
			value = (value << 8) | (data[idx] & 0xFF);
		}
		return value;
	}

}
