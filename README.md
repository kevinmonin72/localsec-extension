# LocalSec Audit - 1-Click Extension 🛡️

Cette extension Chrome vous permet de réaliser des audits de sécurité de n'importe quelle page web, **100% hors-ligne et en un clic**. Elle n'envoie aucune donnée à des serveurs tiers.

## 🚀 Installation

Puisque cette extension est privée, vous devez l'installer via le mode développeur de Chrome :

1. Ouvrez Google Chrome et accédez à l'URL suivante : `chrome://extensions/`
2. En haut à droite, activez le bouton **"Mode développeur"** (Developer mode).
3. Cliquez sur le bouton **"Charger l'extension non empaquetée"** (Load unpacked) en haut à gauche.
4. Sélectionnez le dossier contenant ce fichier (`localsec-extension`).

C'est tout ! L'icône de l'extension devrait apparaître dans votre barre de navigation.

## 🛠️ Développement (Build)

Si vous modifiez le fichier source `popup-src.js`, vous devez recompiler l'extension.

1. Installez les dépendances :
   ```bash
   npm install
   ```
2. Lancez la compilation :
   ```bash
   npm run build
   ```
3. Retournez sur `chrome://extensions/` et cliquez sur l'icône "Actualiser" (flèche circulaire) sur la carte de l'extension.

## 🎯 Utilisation
1. Naviguez sur une des pages web que vous souhaitez auditer.
2. Cliquez sur l'extension, puis sur **"Lancer l'audit (1 Clic)"**.
3. Un rapport HTML s'ouvrira dans un nouvel onglet avec vos résultats.
