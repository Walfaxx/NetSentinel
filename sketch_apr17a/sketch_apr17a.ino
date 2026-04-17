#include <WiFi.h>
#include <ESP32Ping.h>
#include <Preferences.h>
#include <lwip/etharp.h>
#include <lwip/netif.h>

Preferences preferences;

void setup() {
  Serial.begin(115200);

  preferences.begin("wifi-config", false);

  String ssid = preferences.getString("ssid", "");
  String pass = preferences.getString("pass", "");

  if (ssid != "") {
    Serial.print("Connexion WiFi: ");
    Serial.println(ssid);
    WiFi.begin(ssid.c_str(), pass.c_str());

    int attempts = 0;
    while (WiFi.status() != WL_CONNECTED && attempts < 40) {
      delay(500);
      attempts++;
    }

    if (WiFi.status() == WL_CONNECTED) {
      Serial.print("WiFi OK, IP: ");
      Serial.println(WiFi.localIP());
    } else {
      Serial.println("WiFi ECHEC");
    }
  } else {
    Serial.println("Aucun WiFi configuré");
  }
}

void loop() {
  if (Serial.available() > 0) {
    String msg = Serial.readStringUntil('\n');
    msg.trim();

    if (msg.length() == 0) return;

    if (msg.startsWith("WIFI_CONFIG:")) {
      configurerWiFi(msg);
    } else if (msg.indexOf("-") >= 0) {
      lancerScan(msg);
    }
  }
}

void configurerWiFi(String data) {
  int firstColon = data.indexOf(':');
  int secondColon = data.indexOf(':', firstColon + 1);

  if (firstColon != -1 && secondColon != -1) {
    String newSsid = data.substring(firstColon + 1, secondColon);
    String newPass = data.substring(secondColon + 1);

    preferences.putString("ssid", newSsid);
    preferences.putString("pass", newPass);

    Serial.println("CONFIG_OK");
    delay(1000);
    ESP.restart();
  }
}

// Récupère l'adresse MAC depuis le cache ARP (peuplé automatiquement après un ping)
String getMACfromARP(IPAddress ip) {
  struct ip4_addr ipaddr;
  IP4_ADDR(&ipaddr, ip[0], ip[1], ip[2], ip[3]);

  struct netif    *netif   = netif_default;
  struct eth_addr *eth_ret = nullptr;
  const ip4_addr_t *ip_ret = nullptr;

  if (etharp_find_addr(netif, &ipaddr, &eth_ret, &ip_ret) >= 0) {
    char mac[18];
    sprintf(mac, "%02X:%02X:%02X:%02X:%02X:%02X",
            eth_ret->addr[0], eth_ret->addr[1], eth_ret->addr[2],
            eth_ret->addr[3], eth_ret->addr[4], eth_ret->addr[5]);
    return String(mac);
  }
  return "";
}

void lancerScan(String range) {
  int dashIndex = range.indexOf('-');
  String startIP = range.substring(0, dashIndex);
  String endIP   = range.substring(dashIndex + 1);

  int lastDot   = startIP.lastIndexOf('.');
  String baseIP = startIP.substring(0, lastDot + 1);

  int startNode = startIP.substring(lastDot + 1).toInt();
  int endNode   = endIP.substring(endIP.lastIndexOf('.') + 1).toInt();

  for (int i = startNode; i <= endNode; i++) {
    String currentIP = baseIP + String(i);
    IPAddress ip;

    if (ip.fromString(currentIP) && Ping.ping(ip, 1)) {
      delay(50); // laisse le temps à lwIP de peupler l'ARP

      String mac = getMACfromARP(ip);
      if (mac.length() == 0) {
        // Fallback : pseudo-MAC basé sur l'IP si ARP indisponible
        mac = "IP:" + currentIP;
      }

      Serial.print("FOUND:");
      Serial.print(currentIP);
      Serial.print("|");
      Serial.print(mac);
      Serial.print("|");
      Serial.println("Appareil_" + currentIP);
    }
  }
  Serial.println("SCAN_TERMINE");
}
