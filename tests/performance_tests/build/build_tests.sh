cmake . -DCMAKE_BUILD_TYPE=Release -DSANITIZER=thread
make -B -j8
