# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.

## [2.0.0](https://github.com/simllll/node-radius-server/compare/v1.2.1...v2.0.0) (2022-04-07)


### Features

* allow setting vlan for authenticated users ([7022750](https://github.com/simllll/node-radius-server/commit/7022750c9831f72b797c7d528fd0300fe4023045))
* restructure to allow usage in other mode projects ([#269](https://github.com/simllll/node-radius-server/issues/269)) ([341e9d2](https://github.com/simllll/node-radius-server/commit/341e9d2aea7ab2838c7e3af2e8e4b7d9918bf1f3))


### Bug Fixes

* cleaner output ([9dc8771](https://github.com/simllll/node-radius-server/commit/9dc8771a21963a138e9f8b706b7554bc13c12955))
* skip username on auth response ([7450673](https://github.com/simllll/node-radius-server/commit/74506735eaa52bc1840eea3f9aa1dd30cb718352))

### [1.2.1](https://github.com/simllll/node-radius-server/compare/v1.2.0...v1.2.1) (2021-10-29)


### Bug Fixes

* parse large responses correclty ([ef82a99](https://github.com/simllll/node-radius-server/commit/ef82a9991153f636de7acaa7c3024a04d7c9b2a7))
* pkg upgrades and small fixes ([5290ac3](https://github.com/simllll/node-radius-server/commit/5290ac37c0da907b2e59a0b2cf20a8f8e473baca))
* remove empty bytes from password buffer in StaticAuth [#116](https://github.com/simllll/node-radius-server/issues/116) ([a06026f](https://github.com/simllll/node-radius-server/commit/a06026f8876656bb7bc5bb6218cf1550e4ea9945))

## [1.2.0](https://github.com/simllll/node-radius-server/compare/v1.1.10...v1.2.0) (2021-01-23)


### Features

* new auth mechnasimn via http post ([#99](https://github.com/simllll/node-radius-server/issues/99)) ([279541a](https://github.com/simllll/node-radius-server/commit/279541a669ca9b70847c7c25f265f1bf77bc8a51))

### [1.1.10](https://github.com/simllll/node-radius-server/compare/v1.1.9...v1.1.10) (2020-12-01)

### [1.1.9](https://github.com/simllll/node-radius-server/compare/v1.1.8...v1.1.9) (2020-09-03)

### [1.1.8](https://github.com/simllll/node-radius-server/compare/v1.1.7...v1.1.8) (2020-09-03)


### Bug Fixes

* **tls:** allow tls v1.0 ([55e6dc4](https://github.com/simllll/node-radius-server/commit/55e6dc4b0b2ddc2d24704a0ef57c56b8905e7aa4))

### [1.1.7](https://github.com/simllll/node-radius-server/compare/v1.1.5...v1.1.7) (2020-08-05)


### Bug Fixes

* session resumptions + google ldap auth ([66fbcf4](https://github.com/simllll/node-radius-server/commit/66fbcf4ca83cc6c3813b0015c0e2d8f69c8db6e6))

### [1.1.6](https://github.com/simllll/node-radius-server/compare/v1.1.5...v1.1.6) (2020-08-05)


### Bug Fixes

* **google-auth:** search base must include ou ([a3ab393](https://github.com/simllll/node-radius-server/commit/a3ab393379be7f1b8b2f82347bbc4300b8db409d))

### [1.1.5](https://github.com/simllll/node-radius-server/compare/v1.1.4...v1.1.5) (2020-06-26)


### Bug Fixes

* **eap:** catch decoding errors ([97ea3fa](https://github.com/simllll/node-radius-server/commit/97ea3fad1d8d1d79eab38ee5e45e17ef6ed20caa))
* **eap:** concat buffers if they are an array ([3d03658](https://github.com/simllll/node-radius-server/commit/3d03658a43a924017ad5da84599f57a21b3ae27e))
* **eap:** output state on error ([e71f0b3](https://github.com/simllll/node-radius-server/commit/e71f0b3d804070f67ad2d42880c516ce612ee7b0))
* **eap-ttls:** reset last processed identifier ([7179c16](https://github.com/simllll/node-radius-server/commit/7179c1682d33ead0e00d7aae17a97428f1fa4ea5))

### [1.1.4](https://github.com/simllll/node-radius-server/compare/v1.1.3...v1.1.4) (2020-06-24)

### [1.1.3](https://github.com/simllll/node-radius-server/compare/v1.1.2...v1.1.3) (2020-05-14)

### [1.1.2](https://github.com/simllll/node-radius-server/compare/v1.1.1...v1.1.2) (2020-03-02)

### [1.1.1](https://github.com/simllll/node-radius-server/compare/v1.1.0...v1.1.1) (2020-03-02)


### Bug Fixes

* **auth:** cache only valid results for one day ([a8a0247](https://github.com/simllll/node-radius-server/commit/a8a02478ce522eb51c46517b4176aa0d50481676))
* **config:** use __dirname to resolve path to ssl certs ([7a28a0d](https://github.com/simllll/node-radius-server/commit/7a28a0dc6bfbae307765e03f4b15c57c84fa0dc2))
* **docs:** fix some typos ([5519391](https://github.com/simllll/node-radius-server/commit/5519391aa3c688422da8d98a3bd789615738b974))

## [1.1.0](https://github.com/simllll/node-radius-server/compare/v1.0.0...v1.1.0) (2020-02-28)


### Features

* **cli:** allow setting config vars via cli ([d9ff95b](https://github.com/simllll/node-radius-server/commit/d9ff95bbbbea9ade9721e3f5d4dc2323988da3d6))

## 1.0.0 (2020-02-27)


### Features

* **ssl:** enable session resumptions for even quicker reintinaliztions :) ([e1b4bb5](https://github.com/simllll/node-radius-server/commit/e1b4bb5597ac74f10b120a5f8cfef7b407a48c8f))
* add debug pkg to reduce output ([9fe25a8](https://github.com/simllll/node-radius-server/commit/9fe25a8b497071ea9276785b7f7710ae0e1e88f8))
* add more auth providers and cleanup google auth ([3f600c6](https://github.com/simllll/node-radius-server/commit/3f600c664ffa7315053d47773c7f9d5060b68d32))
* inner tunnel for TTSL support added ([6aa4b9f](https://github.com/simllll/node-radius-server/commit/6aa4b9f92efb271ee327d3d70bccba27284304ee))


### Bug Fixes

* **docs:** better file names ([5897498](https://github.com/simllll/node-radius-server/commit/589749883c4c881c3af753530987d6f57d8d809d))
* improve coping with long running auth requests ([7ca60a2](https://github.com/simllll/node-radius-server/commit/7ca60a20cc24eb8100ed1f20fe18e7ec664fd176))
* **auth:** improve google auth ([0baf815](https://github.com/simllll/node-radius-server/commit/0baf8155bf74fed9e08826b1aea8242f72c81878))
* **docs:** add examples ([a3ed0be](https://github.com/simllll/node-radius-server/commit/a3ed0be02db0a7fcd89544c89d9b0ee11e949808))
* docs ([cca4dce](https://github.com/simllll/node-radius-server/commit/cca4dce96142d2b2d04b419bd7500e3841262235))
* ldap auth failed auth and added test scripts ([5e5005c](https://github.com/simllll/node-radius-server/commit/5e5005cf6bcbc3d9450db3651478249f8deb92a6))
* ssl again ([a624bc1](https://github.com/simllll/node-radius-server/commit/a624bc15b0e1fde4f2a268c62500b090e4f366a5))
* **ssl:** move files ([f53a423](https://github.com/simllll/node-radius-server/commit/f53a42335bb583af7575b8cf5fcf5fe58cdeaed4))
* a lot of bug fixes, first running version for windows and android :) ([0cb807a](https://github.com/simllll/node-radius-server/commit/0cb807a555febec461edf1280fe1a7e1b72186b0))
* a lot of bug fixes, first running version for windows and android :) ([4989c2b](https://github.com/simllll/node-radius-server/commit/4989c2b6bc162a1688e84c21919835cb8637854c))
* add MS-MPPE-Send-Key and MS-MPPE-Recv-Key ([7e28c60](https://github.com/simllll/node-radius-server/commit/7e28c60d81abe4c2c5269babbf6ef5951d65d682))
* eap call is using wrong this, needs more refactoring later ([837453f](https://github.com/simllll/node-radius-server/commit/837453fca250abb45f1069405b96e29fc0e3e9c4))

# Changelog

All notable changes to this project will be documented in this file. See [standard-version](https://github.com/conventional-changelog/standard-version) for commit guidelines.
