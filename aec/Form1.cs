using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.IO;

namespace aec
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
            
        }


        public static string Encrypt(string Text, byte[] key, byte[] VectorBytes)
        {
            try
            {

                byte[] TextBytes = Encoding.UTF8.GetBytes(Text);
                RijndaelManaged rijKey = new RijndaelManaged();
                rijKey.Mode = CipherMode.CBC;            
                ICryptoTransform encryptor = rijKey.CreateEncryptor(key,VectorBytes);                
                MemoryStream memoryStream = new MemoryStream();             
                CryptoStream cryptoStream = new CryptoStream(memoryStream,encryptor,CryptoStreamMode.Write);               
                cryptoStream.Write(TextBytes, 0, TextBytes.Length);               
                cryptoStream.FlushFinalBlock();               
                byte[] cipherTextBytes = memoryStream.ToArray();
                memoryStream.Close();
                cryptoStream.Close();                
                string cipherText = Convert.ToBase64String(cipherTextBytes);                
                return cipherText;
            }            
            catch (Exception e)
            {
                MessageBox.Show("Falsches Passwort "+ e.Message.ToString());
                string t = "";
                return t;
            }
        }

        public static string Decrypt(string Text, byte[] keyBytes, byte[] VectorBytes)
        {
            try
            {
                byte[] TextBytes = Convert.FromBase64String(Text);                
                RijndaelManaged rijKey = new RijndaelManaged();
                rijKey.Mode = CipherMode.CBC;
                ICryptoTransform decryptor = rijKey.CreateDecryptor(keyBytes,VectorBytes);
                MemoryStream memoryStream = new MemoryStream(TextBytes);
                CryptoStream cryptoStream = new CryptoStream(memoryStream,decryptor,CryptoStreamMode.Read);
                byte[] pTextBytes = new byte[TextBytes.Length];
                int decryptedByteCount = cryptoStream.Read(pTextBytes,0,pTextBytes.Length);
                memoryStream.Close();
                cryptoStream.Close();
                string plainText = Encoding.UTF8.GetString(pTextBytes,0,decryptedByteCount);
                return plainText;
            }
            catch (Exception a)
            {
                MessageBox.Show("The Passkey "+ a.Message.ToString());
                string t = "";
                return t;
            }
        }


        private void button1_Click(object sender, EventArgs e)
        {

            byte[] salt = { 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] V = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            PasswordDeriveBytes cdk = new PasswordDeriveBytes(textBox4.Text,salt);
            //string kex = Convert.ToBase64String(cdk.CryptDeriveKey("RC2", "SHA1", 128, salt));
            byte[] kex = cdk.CryptDeriveKey("RC2", "SHA1", 128, salt);
                string answer = Encrypt(textBox3.Text, kex,V);
                textBox1.Text = answer;

        }

        private void textBox4_TextChanged(object sender, EventArgs e)
        {

        }

        private void button2_Click(object sender, EventArgs e)
        {
            byte[] salt = { 0, 0, 0, 0, 0, 0, 0, 0 };
            byte[] V = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            PasswordDeriveBytes cdk = new PasswordDeriveBytes(textBox4.Text, salt);
            //string kex = Convert.ToBase64String(cdk.CryptDeriveKey("RC2", "SHA1", 128, salt));
            byte[] kex = cdk.CryptDeriveKey("RC2", "SHA1", 128, salt);
                string answer = Decrypt(textBox1.Text, kex, V);
                textBox3.Text = answer;

            }
    }
}