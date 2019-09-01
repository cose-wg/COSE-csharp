#!/bin/bash

set -ev
ls

echo $SLN
echo $VERSION
echo $TARGET

ls

cd COSE

#mono ../nuget.exe restore $SLN
#nuget.exe restore $SLN

# $NUGET restore $SLN
dotnet build --configuration $VERSION /p:platform="Any CPU" $SLN
#xbuild /p:Configuration=$VERSION $SLN

# mono ../testrunner/NUnit.ConsoleRunner.3.5.0/tools/nunit3-console.exe ./COSE.Tests/bin/$VERSION/$TARGET/COSE.Tests.dll

