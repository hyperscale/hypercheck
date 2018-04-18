Hypercheck ![Last release](https://img.shields.io/github/release/hyperscale/hypercheck.svg)
=========

![hypercheck logo](https://cdn.rawgit.com/hyperscale/hypercheck/master/_resources/hypercheck.svg "hypercheck logo")


[![Go Report Card](https://goreportcard.com/badge/github.com/hyperscale/hypercheck)](https://goreportcard.com/report/github.com/hyperscale/hypercheck)

| Branch  | Status | Coverage |
|---------|--------|----------|
| master  | [![Build Status](https://img.shields.io/travis/hyperscale/hypercheck/master.svg)](https://travis-ci.org/hyperscale/hypercheck) | [![Coveralls](https://img.shields.io/coveralls/hyperscale/hypercheck/master.svg)](https://coveralls.io/github/hyperscale/hypercheck?branch=master) |
| develop | [![Build Status](https://img.shields.io/travis/hyperscale/hypercheck/develop.svg)](https://travis-ci.org/hyperscale/hypercheck) | [![Coveralls](https://img.shields.io/coveralls/hyperscale/hypercheck/develop.svg)](https://coveralls.io/github/hyperscale/hypercheck?branch=develop) |

Hypercheck is a fonctional monitoring platform.

Install
-------

### Docker

```shell
docker pull hyperscale/hypercheck
```

### MacOS

Install dependencies with dep:
```shell
dep ensure
```

Build hypercheck:
```shell
make build
```

Run hypercheck
```shell
./hypercheck
```

Documentation
-------------

[Hpercheck API Reference](https://hyperscale.github.io/hypercheck/)

License
-------

Hpercheck is licensed under [the MIT license](LICENSE.md).
