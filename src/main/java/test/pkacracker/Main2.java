package test.pkacracker;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.EAXBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.zip.*;

public class Main2 {
    private final static byte[] key = new byte[]{-119, -119, -119, -119,
            -119, -119, -119, -119, -119, -119, -119, -119, -119, -119, -119, -119};
    private final static byte[] iv = new byte[]{ 16, 16, 16, 16, 16, 16,
            16, 16, 16, 16, 16, 16, 16, 16, 16, 16 };

    //шифрование
    //todo
    //еще сырой код на примере файла testpka.xml
    public static void main(String[] args) throws IOException, InvalidCipherTextException {
        /*
        Считываем байты из файла
        */
        byte[] input = Files.readAllBytes(Paths.get("testpka.xml"));
        /*
        Этап 1
        Запаковываем в zlib архив, функция pack представлена ниже
        */
        byte[] compressed = pack(input);
        byte[] encrypted = new byte[compressed.length * 2];

        /*
        Этап 2
        Обфускация
        b[i] = a[i] ^ (l - i)
        l - длина запакованного архива
        a - массив байт запакованного архива
        b - выходной массив байт
        */
        for (int i = 0; i < compressed.length; i++) {
            compressed[i] = (byte) (compressed[i] ^ (compressed.length - i));
        }

        /*
        Этап 3
        Шифрование
        Используется алгоритм twofish в связке с eax mode
        Ключом является массив длины 16 байт со значениями -119
        Параметром iv является массив длины 16 байт со значениями 16
        */
        TwofishEngine twofishEngine = new TwofishEngine();
        EAXBlockCipher d = new EAXBlockCipher(twofishEngine);
        final KeyParameter aesKey = new KeyParameter(key);
        CipherParameters cipherParameters = new ParametersWithIV(aesKey, iv);
        d.init(true, cipherParameters);
        // шифруем
        int trueLength = d.processBytes(compressed, 0, compressed.length, encrypted, 0);
        // добавляем MAC
        int addLength = d.doFinal(encrypted, trueLength);

        //непонятно откуда берутся последние 8 байт, для файла testpka.xml они представлены ниже
        encrypted = Arrays.copyOfRange(encrypted, 0, trueLength + addLength + 8);
        byte[] mac = d.getMac();
        System.out.println(Arrays.toString(mac));
        int blockSize = d.getBlockSize();
        encrypted[encrypted.length - 1] = -66;
        encrypted[encrypted.length - 2] = 14;
        encrypted[encrypted.length - 3] = -96;
        encrypted[encrypted.length - 4] = -38;
        encrypted[encrypted.length - 5] = 119;
        encrypted[encrypted.length - 6] = 74;
        encrypted[encrypted.length - 7] = -77;
        encrypted[encrypted.length - 8] = 30;


        byte[] output = new byte[encrypted.length];

        /*
        Этап 4
        Обфускация
        b[i + ~i] = a[i] ^ (l - i * l)
        l - длина зашифрованных байт
        a - массив зашифрованных байт
        b - выходной массив байт файла pka
        */

        for (int i = 0; i < encrypted.length; i++) {
            output[encrypted.length + ~i] = (byte) (encrypted[i] ^ (encrypted.length - i * encrypted.length));
        }

        System.out.println();
        System.out.println(output[0]);
        System.out.println(output[1]);
        System.out.println(output[2]);
        System.out.println(output[3]);

        /*
        Запись в файл pka
        */
        FileOutputStream fileOutputStream = new FileOutputStream("encrypted.pka");
        fileOutputStream.write(output);
        fileOutputStream.close();
    }
    public static byte[] pack(byte[] bytes) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] length = ByteBuffer.allocate(4).putInt(bytes.length).array();
        out.write(length);
        DeflaterOutputStream dout = new DeflaterOutputStream(out);
        dout.write(bytes);
        dout.close();
        return out.toByteArray();
    }

    //расшифровка
    public static void decrypt(String fromFile, String toFile) throws IOException, DataFormatException {
        /*
        Считываем байты из файла
        */
        byte[] input = Files.readAllBytes(Paths.get(fromFile));
        int length = input.length;
        byte[] processed = new byte[length];
        byte[] output = new byte[length];

        /*
        Этап 1
        Деобфускация
        b[i] = a[l + ~i] ^ (l - i * l)
        l - общее количество байт в файле
        a - входной массив байтов
        b - выходной массив байтов
        */

        for (int i = 0; i < length; i++) {
            processed[i] = (byte) (input[length + ~i] ^ (length - i * length));
        }

        /*
        Этап 2
        Расшифровка
        Используется алгоритм twofish в связке с eax mode
        Ключом является массив длины 16 байт со значениями -119
        Параметром iv является массив длины 16 байт со значениями 16
        */

        EAXBlockCipher d = new EAXBlockCipher(new TwofishEngine());
        final KeyParameter aesKey = new KeyParameter(key);
        CipherParameters cipherParameters = new ParametersWithIV(aesKey, iv);
        d.init(false, cipherParameters);
        int trueLength = d.processBytes(processed, 0, length, output, 0);
        output = Arrays.copyOfRange(output, 0, trueLength - 2); //почему-то приходится отрезать последние 2 байта

        /*
        Этап 3
        Деобфускация
        b[i] = a[l] ^ (l - i)
        l - длина расшифрованного массива байт
        a - входной расшифрованный массив байт
        b - выходной массив байт
        */

        for (int i = 0; i < output.length; i++) {
            output[i] = (byte) (output[i] ^ (output.length - i));
        }

        /*
        Распаковка полученного zlib архива
        */
        //первый 4 байта - длина исходного архива
        ByteBuffer bb = ByteBuffer.wrap(new byte[]{output[0], output[1], output[2], output[3]});
        bb.order(ByteOrder.BIG_ENDIAN);
        int len = bb.getInt();

        //собственно распаковка не включая первые 4 байта
        Inflater decompresser = new Inflater();
        decompresser.setInput(output, 4, output.length - 4);
        byte[] result = new byte[len];
        int resultLength = decompresser.inflate(result);
        decompresser.end();

        /*
        Запись в файл
        */

        FileOutputStream outputStream = new FileOutputStream(toFile);
        outputStream.write(result);
        outputStream.close();
    }

}

