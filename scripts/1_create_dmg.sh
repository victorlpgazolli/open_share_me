set -euo pipefail

rm -rf dmg_staging OpenShareMe.dmg
mkdir -p dmg_staging

cp -r DerivedData/Build/Products/Release/OpenShareMe.app dmg_staging/

ln -s /Applications dmg_staging/Applications

hdiutil create -volname "OpenShareMe Installer" -srcfolder dmg_staging -ov -format UDZO OpenShareMe.dmg