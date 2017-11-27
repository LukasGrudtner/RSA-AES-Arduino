#include <SPI.h>         // needed for Arduino versions later than 0018
#include <Ethernet.h>
#include <EthernetUdp.h>         // UDP library from: bjoern@cs.stanford.edu 12/30/2008
#include <math.h>
#include <string.h>
#include "AESLib.h"

// Enter a MAC address and IP address for your controller below.
byte mac[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED};
// The IP address will be dependent on your local network:
IPAddress ip(150, 162, 63, 157);
IPAddress pc(150, 162, 63, 202);

int localPort = 8887;      // local port to listen on

// buffers for receiving and sending data
char packetBuffer[UDP_TX_PACKET_MAX_SIZE];  //buffer to hold incoming packet,
char  ReplyBuffer[38];//[] = "acknowledged";       // a string to send back
char  temp[38];
String replay;

int DH = 1;
int RSA = 2;

int a = 2;
int g = 23;
int p = 86;

boolean chaveRSArecebida = false;
boolean chaveDHrecebida = false;

int my_pub = 9827;
int my_priv = 3786;
int java_pub;
int iv = 8;

int simpleKey;
boolean keyExchange = false;

// An EthernetUDP instance to let us send and receive packets over UDP
EthernetUDP Udp;

void setup() {
  
  // start the Ethernet and UDP:
  Ethernet.begin(mac, ip);
  Udp.begin(localPort);
  Serial.begin(9600);
  Serial.println("Start");
}

void loop() {

  /* Envia chave pública RSA uma única vez. */
  if (RSA) {
    RSA--;

    char rsabuf[32];
    char ivbuf[8];

    sprintf(rsabuf, "%i", my_pub);
    sprintf(ivbuf, "%i", iv);

    /* Concatena chave pública, # e iv em rsabuf. */
    strcat(rsabuf, "#");
    strcat(rsabuf, ivbuf);
    
    /* Realiza envio da chave. */
    Udp.beginPacket(pc, localPort);
    Udp.write(rsabuf);
    Udp.endPacket();

    Serial.println("*** Chave pública RSA enviada! ***");
    Serial.print("Chave pública do cliente # iv: ");
    Serial.println(rsabuf);
    Serial.println("***********************************");

    delay(3000);
    
  }

  /* Recebe chave pública RSA uma única vez. */
  if (!chaveRSArecebida) {
    
    int packetSize = Udp.parsePacket();

    if (packetSize) {
      Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);

      /* Remove chave pública do Servidor do buffer. */
      int i = 0;
      char java_pub_string[32];
      while (packetBuffer[i] != '#') {
        java_pub_string[i] = packetBuffer[i];
        i++;
      }
      i++;
      java_pub = atoi(java_pub_string);
      
      /* Remove iv do buffer. */
      int iv_recebido;
      char iv_recebido_string[8];
      int j = 0;
      while (packetBuffer[i] != '\0') {
        iv_recebido_string[j] = packetBuffer[i];
        j++;
        i++;
      }
      iv_recebido = atoi(iv_recebido_string);

      Serial.println("*** Chave pública RSA recebida do Server! ***");
      Serial.print("Chave pública do Server: ");
      Serial.println(java_pub);
      Serial.print("Iv: ");
      Serial.println(iv_recebido);
      Serial.println("**********************************************");

      if ((iv_recebido-1) == iv)
        Serial.println("O iv recebido está correto.");
      else
        Serial.println("O iv recebido está incorreto.");
      
      // clear the char arrays for the next receive packet and send
      memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
      memset(packetBuffer, 0, sizeof(packetBuffer));

      chaveRSArecebida = true;
  
      Serial.println("*** Troca de chaves RSA concluída! ***\n");
      delay(3000);
    }
  }

  /* Faz a troca de chaves Diffie-Hellman uma única vez, sem criptografia. */
  if (DH) {
    DH--;

    /* Envio da primeira chave. */
    int aux = (int) pow(g, a);
    int envio = aux % p;
    char bufP[10];
    char bufG[10];
    char bufIv[10];
    char buf[32];

    /* Passa os valores p, g e iv para string. */
    sprintf(bufP, "%i", p);
    sprintf(bufG, "%i", g);
    sprintf(bufIv, "%i", iv);
    
    sprintf(buf, "%i", envio);

    /* Concatena p, g e iv no buffer. */
    strcat(buf, "#");
    strcat(buf, bufP);
    strcat(buf, "#");
    strcat(buf, bufG);
    strcat(buf, "#");
    strcat(buf, bufIv);
    
    /* Realiza envio da chave. */
    Udp.beginPacket(pc, localPort);
    Udp.write(buf);
    Udp.endPacket();

    Serial.println("*** Chave Diffie-Hellman enviada! ***");
    Serial.print("A: ");
    Serial.println(envio);
    Serial.print("p: ");
    Serial.println(bufP);
    Serial.print("g: ");
    Serial.println(bufG);
    Serial.print("iv: ");
    Serial.println(bufIv);
    Serial.println("*************************************");

    delay(3000);
  }
  
  if (!chaveDHrecebida) {

    int packetSize = Udp.parsePacket();
    /* Recebeu chave. */
    if (packetSize) {
      Udp.read(packetBuffer, UDP_TX_PACKET_MAX_SIZE);
  
      /* Recupera chave do Servidor do buffer. */
      int value;
      char valueBuff[32];
      char valueBuf[32];

      Serial.print("ValueBuf: ");
      Serial.println(valueBuf);

      int i = 0;
      while (packetBuffer[i] != '#') {
        valueBuf[i] = packetBuffer[i];
        i++;
      }
      i++;

      
      
      value = atoi(valueBuf);

      Serial.print("Value: ");
      Serial.println(value);

      int aux = (int) pow(value, a);
      simpleKey = aux % p;
      
      /* Remove iv do buffer. */
      int iv_recebido;
      char iv_recebido_string[2];
      int j = 0;
      Serial.print("PACKET BUFFER: ");
      Serial.println(packetBuffer);
//      Serial.println(packetBuffer[i]);
      
//      while (packetBuffer[i] != '\0') {
//        iv_recebido_string[j] = packetBuffer[i];
//        j++;
//        i++;
//      }
      
//      iv_recebido = atoi(iv_recebido_string);
//      iv_recebido = atoi(packetBuffer[i]);
      iv_recebido = strtol(packetBuffer[i], (char **)NULL, 10);
//      strtol(str, (char **)NULL, 10)

      Serial.print("Packet buffer: ");
      Serial.println(packetBuffer[i]);

      Serial.println("*** Chave Diffie-Hellman recebida! ***");
      Serial.print("Simple key: ");
      Serial.println(simpleKey);
      Serial.print("iv: ");
      Serial.println(iv_recebido);
      Serial.println("**************************************");

      if ((iv_recebido-1) == iv)
        Serial.print("O iv recebido está correto.");
      else
        Serial.println("O iv recebido está incorreto.");
      
      // clear the char arrays for the next receive packet and send
      memset(ReplyBuffer, 0, sizeof(ReplyBuffer));
      memset(packetBuffer, 0, sizeof(packetBuffer));

      chaveDHrecebida = true;
  
      Serial.println("*** Troca de chaves Diffie-Hellman finalizada! ***");
      delay(3000);
    }
  }

  /* Com as chaves trocadas: */
  if (chaveDHrecebida && !chaveDHrecebida) {
    uint8_t key[16];
    uint8_t iv[16];
    int j;
    for (j = 0; j < 16; j++) { key[j] = simpleKey; iv[j] = j+1; }
    char data[] = "0123456789012345";
    const uint16_t data_len = 16;

    /********************************************************/
    /* Imprime data em hexadecimal no Serial (CHAR -> HEX) */
    
    char buf[48];
    char aux[2];
    int q, l;
    l = 0;
    Serial.print("\nTexto em HEX SEM CRIPTOGRAFIA: ");
    
    for (q = 0; l < data_len; q += 2) {
      sprintf(aux, "%X", data[l]);
      buf[q] = aux[0];
      buf[q+1] = aux[1];
      l++;
      Serial.print(aux);
      Serial.print(" ");
    }
     /********************************************************/

    aes192_cbc_enc(key, iv, data, data_len);
    Serial.print("\nencrypted:");
    Serial.println(data);

    /********************************************************/
    /* Imprime data criptografada em hexadecimal no Serial (CHAR -> HEX) */
    
    char auxi[2];
    int q1, l1;
    l = 0;
    Serial.print("\nTexto em HEX COM CRIPTOGRAFIA: ");
    
    for (q1 = 0; l1 < data_len; q1 += 2) {
      sprintf(auxi, "%X", data[l1]);
      buf[q1] = auxi[0];
      buf[q1+1] = auxi[1];
      l1++;
      Serial.print(auxi);
      Serial.print(" ");
    }
     /********************************************************/

    /* Envio da informação criptografada para o Java. */
    Udp.beginPacket(pc, localPort);
    Udp.write(data);
    Udp.endPacket();
    
    aes192_cbc_dec(key, iv, data, data_len);
    Serial.print("\ndecrypted:");
    Serial.println(data);
    Serial.print("*******************************************************");
    delay(5000);
  }

}



