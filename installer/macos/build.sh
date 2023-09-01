#!/bin/bash
set -e

# parameters
SCRIPTPATH="$( cd -- "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"
TARGET_DIRECTORY="$SCRIPTPATH/target"
PRODUCT="OCO Agent"
VERSION="1.0.2"
TARGET_FILENAME="oco-agent.pkg"
APPLE_DEVELOPER_CERTIFICATE_ID="Georg Sieber (96G8V7UY3M)"


# create/clean target build directory
if [ -d "${TARGET_DIRECTORY}" ]; then
	sudo rm -rf "$TARGET_DIRECTORY"
fi
mkdir -p "$TARGET_DIRECTORY"

cp -r "$SCRIPTPATH/darwin" "${TARGET_DIRECTORY}/"
chmod -R 755 "${TARGET_DIRECTORY}/darwin/scripts"
chmod -R 755 "${TARGET_DIRECTORY}/darwin/Resources"
chmod 644 "${TARGET_DIRECTORY}/darwin/Distribution"


# prepare installer files
sed -i '' -e "s/__VERSION__/$VERSION/g" "${TARGET_DIRECTORY}/darwin/Distribution"
sed -i '' -e "s/__PRODUCT__/$PRODUCT/g" "${TARGET_DIRECTORY}/darwin/Distribution"
sed -i '' -e "s/__FILENAME__/$TARGET_FILENAME/g" "${TARGET_DIRECTORY}/darwin/Distribution"

#sed -i '' -e "s/__VERSION__/$VERSION/g" "${TARGET_DIRECTORY}"/darwin/Resources/*.html
#sed -i '' -e "s/__PRODUCT__/$PRODUCT/g" "${TARGET_DIRECTORY}"/darwin/Resources/*.html


# copy files in place
mkdir -p "${TARGET_DIRECTORY}/darwinpkg"
mkdir -p "${TARGET_DIRECTORY}/darwinpkg/opt/oco-agent"
mkdir -p "${TARGET_DIRECTORY}/darwinpkg/Library/LaunchDaemons"
cp "../../dist/oco-agent" "${TARGET_DIRECTORY}/darwinpkg/opt/oco-agent/oco-agent"
cp "../../systems.sieber.oco-agent.plist" "${TARGET_DIRECTORY}/darwinpkg/Library/LaunchDaemons/systems.sieber.oco-agent.plist"
chmod 755 "${TARGET_DIRECTORY}/darwinpkg/opt/oco-agent"
chmod 744 "${TARGET_DIRECTORY}/darwinpkg/opt/oco-agent/oco-agent"
chmod 644 "${TARGET_DIRECTORY}/darwinpkg/Library/LaunchDaemons/systems.sieber.oco-agent.plist"
sudo chown -R root:wheel "${TARGET_DIRECTORY}/darwinpkg"

rm -rf "${TARGET_DIRECTORY}/package"
mkdir -p "${TARGET_DIRECTORY}/package"
chmod 755 "${TARGET_DIRECTORY}/package"

rm -rf "${TARGET_DIRECTORY}/pkg"
mkdir -p "${TARGET_DIRECTORY}/pkg"
chmod 755 "${TARGET_DIRECTORY}/pkg"

find "${TARGET_DIRECTORY}" -name ".DS_Store" -delete


# build packages
echo "Build application installer package ..."
pkgbuild --identifier "org.${PRODUCT}.${VERSION}" \
	--version "${VERSION}" \
	--scripts "${TARGET_DIRECTORY}/darwin/scripts" \
	--root "${TARGET_DIRECTORY}/darwinpkg" \
	"${TARGET_DIRECTORY}/package/$TARGET_FILENAME"


echo "Build application installer product ..."
productbuild --distribution "${TARGET_DIRECTORY}/darwin/Distribution" \
	--resources "${TARGET_DIRECTORY}/darwin/Resources" \
	--package-path "${TARGET_DIRECTORY}/package" \
	"${TARGET_DIRECTORY}/pkg/$TARGET_FILENAME"


# sign packages
if [ "$APPLE_DEVELOPER_CERTIFICATE_ID" != "" ]; then
	echo "Sign application installer ..."
	mkdir -pv "${TARGET_DIRECTORY}/pkg-signed"
	chmod 755 "${TARGET_DIRECTORY}/pkg-signed"

	productsign --sign "${APPLE_DEVELOPER_CERTIFICATE_ID}" \
		"${TARGET_DIRECTORY}/pkg/$TARGET_FILENAME" \
		"${TARGET_DIRECTORY}/pkg-signed/$TARGET_FILENAME"

	pkgutil --check-signature "${TARGET_DIRECTORY}/pkg-signed/$TARGET_FILENAME"
fi


# cleanup
rm -rf "${TARGET_DIRECTORY}/package"


echo "Build finished"
