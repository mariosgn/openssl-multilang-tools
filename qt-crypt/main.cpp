#include <QCoreApplication>
#include <QDebug>
#include <QDateTime>
#include <QFile>
#include <QString>
#include <QDataStream>

#include <openssl/aes.h>
#include <openssl/evp.h>

/*

echo hello > plain_text.txt

rm *.ssl *.dxt

./qt-crypt --enc ASD plain_text.txt  qt_encripted.ssl
./qt-crypt --dec ASD qt_encripted.ssl  qt_decoded_text.dxt
openssl enc -e -aes-256-cbc -salt -pass pass:ASD -in plain_text.txt -out ossl_encripted.ssl
openssl enc -d -aes-256-cbc -salt -pass pass:ASD -in ossl_encripted.ssl -out ossl_decoded_text.dxt

to test:

openssl enc -e -aes-256-cbc -salt -pass pass:ASD -in plain_text.txt -out ossl_encripted.ssl
./qt-crypt --dec ASD ossl_encripted.ssl  qt_decoded_text.dxt
cat qt_decoded_text.dxt

./qt-crypt --enc ASD plain_text.txt  qt_encripted.ssl
openssl enc -d -aes-256-cbc -salt -pass pass:ASD -in qt_encripted.ssl -out ossl_decoded_text.dxt
cat ossl_decoded_text.dxt




base64

openssl enc -e -aes-256-cbc -salt -base64 -pass pass:ASD -in plain_text.txt -out ossl_encripted.ssl
./qt-crypt --dec --base64 ASD ossl_encripted.ssl  qt_decoded_text.dxt
cat qt_decoded_text.dxt

./qt-crypt --enc --base64 ASD plain_text.txt  qt_encripted.ssl
openssl enc -d -aes-256-cbc -base64 -salt -pass pass:ASD -in qt_encripted.ssl -out ossl_decoded_text.dxt
cat ossl_decoded_text.dxt



*/


QByteArray encript(const QByteArray &data, const QByteArray &key)
{
    //    QCryptographicHash _hashKey(QCryptographicHash::Sha256);
    //    _hashKey.addData(key);
    //    QByteArray hashKey = _hashKey.result();

    QByteArray saltHeader = "Salted__";

    qsrand((uint)QDateTime::currentDateTime().toTime_t());

    QByteArray res;

    EVP_CIPHER_CTX en;
    unsigned char salt[8];
    unsigned char *key_data = (unsigned char *)key.constData();
    int key_data_len = key.size();

    //buid a salt
    for (int i = 0; i < 8; ++i) {
        salt[i] = qrand()%255;
    }


    QByteArray stllt((const char*)&salt, 8);
//    qDebug( )<< "stllt" << stllt.toHex();

    unsigned char _key[32], iv[32];
    memset(&iv, '\0', 32);
    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(),
                           (unsigned char*)&salt,
                           key_data, key_data_len, 1,
                           _key, iv);
    if (i != 32) {
        qDebug() << "Key size is  bits - should be 256 bits\n" <<  i;
        return res;
    }

    QByteArray ivBa((const char*)iv, 16);
//    qDebug() << "iv" << ivBa.toHex();

    EVP_CIPHER_CTX_init(&en);
    EVP_EncryptInit_ex(&en, EVP_aes_256_cbc(), NULL, _key, iv);

    int c_len = data.size() + AES_BLOCK_SIZE;
    int f_len = 0;
    unsigned char *ciphertext = (unsigned char *)malloc(c_len);

    EVP_EncryptUpdate(&en, ciphertext, &c_len, (unsigned char *)data.constData(), data.size()+1);
    EVP_EncryptFinal_ex(&en, ciphertext+c_len, &f_len);
    res = QByteArray((const char*)ciphertext, c_len + f_len);
    free(ciphertext);
    EVP_CIPHER_CTX_cleanup(&en);
    return saltHeader+QByteArray((const char*)&salt, 8)+res;
}

QByteArray decript(const QByteArray &data, const QByteArray &key)
{
    QByteArray res;

    QByteArray saltHeader = "Salted__";
    int headerSize = 16;
    QByteArray header = data.mid(saltHeader.size(), headerSize-saltHeader.size());

//    qDebug() << "salt" << header.toHex();

    EVP_CIPHER_CTX de;
    unsigned char *salt = (unsigned char *)header.constData();
    unsigned char *key_data = (unsigned char *)key.constData();
    int key_data_len = key.size();


    unsigned char _key[32], iv[32];
    int i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_md5(),
                          salt,
                           key_data, key_data_len, 1,  //TODO: what is this magic number
                           _key, iv);
    if (i != 32) {
      qDebug() << "Key size is  bits - should be 256 bits\n" <<  i;
      return res;
    }

    QByteArray ivBa((const char*)iv, 16);
//    qDebug() << "iv" << ivBa.toHex();

    EVP_CIPHER_CTX_init(&de);
    EVP_DecryptInit_ex(&de, EVP_aes_256_cbc(), NULL, _key, iv);

    QByteArray dataDecr = data.mid(headerSize);

    int p_len = dataDecr.size();
    int f_len = 0;
    unsigned char *plaintext = (unsigned char *)malloc(p_len);

    EVP_DecryptUpdate(&de, plaintext, &p_len, (unsigned char*)dataDecr.constData(), dataDecr.size());
    EVP_DecryptFinal_ex(&de, plaintext+p_len, &f_len);
    res = QByteArray((const char*)plaintext, p_len + f_len);
    free(plaintext);
    EVP_CIPHER_CTX_cleanup(&de);
    return res;
}



int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);

//    QByteArray eb = encript("ciao", "suka");
//    QByteArray p = decript(eb, "suka");

    QStringList args = a.arguments();
    QTextStream err(stderr);

    if (args.size()<4)
    {
        fprintf(stderr, "Usage:\n [--enc|--dec] [--base64] password input_file output_file ");
        return -1;
    }

    bool enc = false;
    if ( args.contains("--enc") )
    {
        enc = true;
    }

    bool base64;
    if ( args.contains("--base64") )
    {
        base64 = true;
    }

    QByteArray pass = QString( args.at( args.size()-3 ) ).toLatin1() ;
    QByteArray infile = QString( args.at( args.size()-2 ) ).toLatin1() ;
    QByteArray outfile = QString( args.at( args.size()-1 ) ).toLatin1() ;

    QFile fIn(infile);
    if (!fIn.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        err << "Cannot open" << args.last();
        return -1;
    }

    QByteArray fInBuff;
    fInBuff = fIn.readAll();

    QByteArray res;
    if (enc)
    {
        err << "Encoding with password " << pass << "\n";
        res = encript(fInBuff, pass);

        if ( base64 )
        {
            err << "Using base64\n";
            res = res.toBase64();
            res.append('/n');
        }
    }
    else
    {
        if ( base64 )
        {
            err << "Using base64\n";
            fInBuff = QByteArray::fromBase64(fInBuff);
        }

        err << "Decoding with password " << pass<< "\n";
        res = decript(fInBuff, pass);
    }

    err << "Writing to " << outfile<< "\n";
    QFile fout(outfile);
    if ( !fout.open(QIODevice::WriteOnly|QIODevice::Truncate))
    {
        err << "Cannot write to " << outfile<< "\n";
        return -1;
    }
    fout.write(res);
    fout.close();

    return 0;
}

