Remove-Item -Recurse -Force build  
cmake -G Ninja -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build