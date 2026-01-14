cmake . -DCMAKE_BUILD_TYPE=Release -DSANITIZER=false
make -B -j8
