if [ "$1" = "" ]; then
    ARCH="x86_64"
else
    ARCH="$1"
fi

# rm -rf build
mkdir -p build
cmake -DARCH=$ARCH . -Bbuild
cd build 
make