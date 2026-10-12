set -euo pipefail

swift Scripts/make-icon.swift Sources/OpenShareMe/Icons/icon.png \
		Sources/OpenShareMe/Resources/Assets.xcassets/AppIcon.appiconset

xcodegen -c

xcodebuild -project OpenShareMe.xcodeproj -scheme OpenShareMe -configuration Release -derivedDataPath ./DerivedData build