
### Contributing to IDAPython

**Note: As of today, we are temporarily not accepting pull requests. We will update this notice once the situation changes. We appreciate your understanding and encourage you to check back later.**

Anyone with a valid license is welcome to contribute to IDAPython, and pull
requests will be honored provided their nature matches the criteria below.

### What can I contribute?

We at Hex-Rays are currently maintaining the official IDAPython repository.

Because we are not an infinite-sized company and thus have limited resources
([interested?](https://hex-rays.com/careers)), we have to keep the
scope of IDAPython itself to a manageable size.

Most of IDAPython consists of rather low-level, arguably non-pythonic APIs.
The reason for that is of course not that we have anything against pythonic
APIs, but we have found that:

- what is idiomatic & pythonic to certain users, will not necessarily be
  to the taste of others,
- when trying to provide pythonic/somewhat higher-level APIs, we often
  ended up not providing the lower-level APIs, sometimes making it
  impossible to build your own utilities should the APIs IDAPython provides
  out-of-the box be insufficient, buggy or just not to your taste,
- users are better at coming up with their own layers anyway.
  E.g., https://github.com/tmr232/Sark

Therefore, the most important aspect of any contribution to IDAPython
should not be about making it more pythonic and/or higher-level, but
instead to make sure that its low-level API (which to a significant degree
are generated from the C/C++ IDA SDK by using SWiG) work fine, are
correctly documented, and tested.

That is the approach we took in order to make sane & well-working
higher-level APIs possible at all.

### Should I write a test?

If your changes touch the APIs from a functional perspective (e.g., fix
a bug, or make a new function available), yes.

There is no such thing as a _code_ change in IDAPython, that is not
accompanied by a test, so please go through the trouble of writing one
so we don't have to do it ourselves.

When it comes to other types of pull requests (e.g., documentation),
it should usually not be necessary to write a test.

See also [the best practices for tests & examples](examples/README.md)


### How to write tests?

**Note: This section is will be updated after setting up the CI**

### Best practices

Please also see [the best practices for developing on IDAPython](docs/howto/swig.md)
