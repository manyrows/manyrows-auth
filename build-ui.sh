#!/bin/bash

cd appkit-ui
npm run build
cd ..
rm -r manyrows-core/appkit/appkit/assets
cp -r appkit-ui/dist/* manyrows-core/appkit

cd appkit-react
npm run build
cd ..

cd manyrows-ui
npm run build
cd ..
rm -r manyrows-core/web/assets
cp -r manyrows-ui/dist/* manyrows-core/web