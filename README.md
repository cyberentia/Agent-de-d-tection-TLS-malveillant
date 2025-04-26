# Agent-de-d-etection-TLS-malveillant

JA3S Defender - Agent de détection TLS malveillant

  

JA3S Defender est un agent de cybersécurité léger, open-source, permettant d'aider à détecter des communications TLS suspectes via l’empreinte JA3S, en interrogeant automatiquement ThreatFox et en suggérant le blocage via le pare-feu Windows.

Fonctionnalités principales

Capture en temps réel des paquets TLS ServerHello (via pyshark)

Extraction de l’empreinte JA3S (hash + string)

Interrogation de ThreatFox pour détection de menaces connues

Affichage d’une alerte visuelle (fenêtre rouge avec Tkinter)

Commande PowerShell prête à copier pour bloquer l'IP malveillante

Lien direct vers VirusTotal pour confirmation manuelle

Fonctionne en mode agent (EXE), sans console

Capture d'écran



Utilisation

Lancer le script Agent.py en environnement Python ou lancer le .exe généré via PyInstaller

L'outil capture les connexions TLS en réseau sur l'interface choisie (Wi-Fi, Ethernet, etc.)

En cas de menace potentielle : une alerte s'affiche + suggestion de blocage

Mode EXE

L’exécutable peut être généré avec :

pyinstaller Agent.py --noconsole

Dépendances Python

pip install -r requirements.txt

pyshark

requests

tkinter

plyer

pyperclip

Cas d’usage

Audit réseau 

Détection de C2 (Command & Control) connus

Analyse comportementale TLS

Outil pédagogique pour démontrer les risques en réseau

Risques / Avertissements

Certaines IP détectées peuvent être des services légitimes (Microsoft, Google) déjà compromis ou utilisés à tort

Le blocage pare-feu via le code fourni via peut affecter des services critiques

Aucune clé API VirusTotal n’est incluse. Le lien VirusTotal est fourni à titre indicatif pour confirmation.

L’outil est à utiliser en tant qu’assistant d’analyse, et non comme unique outil de décision

Cet agent est une ressource supplémentaire qui pourrais améliorer la visibilité sur les connexions réseau

Il pourrait aider à détecter des comportements anormaux précoces (ex : JA3S suspects) mais il ne remplace pas une solution complète de cybersécurité

Il pourrait aider à réduire la surface d'attaque, mais d'autres protections doivent rester en place (antivirus, EDR, firewalls, surveillance humaine...)

Cet outil est fourni "en l’état", sans aucune garantie d’aucune sorte, explicite ou implicite

L'utilisateur assume tous les risques liés à son utilisation. L'outil doit être utilisé comme un complément d'analyse et ne remplace pas les bonnes pratiques de cybersécurité

N'hésitez pas à me contacter pour des versions adaptées en entreprise, ou pour tout accompagnement technique

Ce projet est destiné à un usage d'apprentissage, d'audit ou de détection complémentaire. Il n'est pas conçu pour protéger de manière exhaustive contre toutes les menaces en environnement de production.

License

MIT - libre d'utilisation, modification et redistribution.

TODO

Ajouter support multilingue (FR/EN)

Ajouter configuration manuelle de l’interface

Ajouter système de logs centralisé

Intégration éventuelle d’AbuseIPDB ou d’une base locale de JA3S