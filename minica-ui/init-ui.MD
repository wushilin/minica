# Install Angular JS CLI
$ npm install -g @angular/cli

# Init new UI peoject

$ ng new minica-ui
? Would you like to add Angular routing? Yes
? Which stylesheet format would you like to use? CSS


# Add ng-bootstrap
$ cd minica-ui
$ ng add @angular/material
# Run
$ ng serve --open --proxy-config proxy.conf.js

# Building UI for release
$ sh ./build.sh
