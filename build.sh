set -e

for arch in x86_64 arm32; do
    build_dir=build/$arch

    mkdir -p $build_dir
    cmake -DARCH=$arch . -B$build_dir
    cd $build_dir
    make

    cd ../..

    demo_dir=demo/$arch
    
    # build executable name,demo subdirectory,demo executable name
    for target in cltls_server,s,s \
                  cltls_server,kgc,kgc \
                  cltls_client,c,c \
                  cltls_misc_initializer,,i \
                  cltls_misc_mqtt_client,,mc \
                  cltls_misc_mqtt_server,,ms; do
        IFS=","
        set -- $target

        mkdir -p $demo_dir/$2
        cp $build_dir/$1 $demo_dir/$2/$3
    done
done