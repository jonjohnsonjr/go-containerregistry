# `scrane`

A very scrappy concept implementation of OCI signatures.

This is roughly what I proposed at the original notary meetup at Amazon.

## Scope

For the sake of a tidy demo, some batteries are included in `scrane`, and some hands are waved around many details.
This blurs the lines between the implementation details and what's actually being proposed.

So, to be explicit:

### In scope

A common format for signing artifacts and associated metadata that follows OCI conventions.
In particular, the use of a "signature index" where signatures are stored as a well-known annotation on a descriptor that points to another artifact within the CAS.
For some examples of what this means, see [Variants](#variants).

### Out of scope or implementation details

#### PKI

This does not attempt to solve the general problem of PKI or key management.
It might make sense to have a well-known annotations next to the signature containing hints or fingerprints to help locate public keys.

This does not dictate any particular digital signature algorithm, but should be flexible enough to support anything.

#### Metadata discovery

For the demo, we use a naming convention (tag based on the sha256 of what we're signing) for locating the signature index.

`reg.example.com/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715` has signatures located at `reg.example.com/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715`

Roughly (ignoring ports in the hostname): `s/:/-/g` and `s/@/:/g` to find the signature index.

See [Race conditions](#race-conditions) for some caveats around this strategy.

Alternative implementations could use transparency logs, local filesystem, a separate repository/registry, an explicit reference to a signature index, a new registry API, grafeas, etc.

#### Signing subjects

This demo only works for artifacts stored as "manifests" in the registry.
The proposed mechanism is flexible enough to support signing arbitrary things.

#### Registry-first

The registry is an obvious choice for both storage and distribution of signatures, but artifacts have many other non-registry representations.
The proposed mechanism is flexible enough to work for on-disk artifacts, but the demo assumes we're using the registry for everything.

## Overview

<p align="center">
  <img src="/images/signatures.dot.svg" />
</p>

## Demo

First, we need some keys.

Let's generate a `private.key` and `public.key`.

```
openssl genrsa -out myprivate.pem 512
openssl pkcs8 -topk8 -in myprivate.pem  -nocrypt > private.key
openssl rsa -in myprivate.pem -pubout > public.key
```

### Signing

Now we've got our keys, let's sign an image.

```
$ scrane -key private.key -a author=jonjohnsonjr sign us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
```

I've added `-a author=jonjohnsonjr` just to attach some metadata to the signature.

We can do this multiple times:

```
$ scrane -key private.key -a hello=world sign us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
```

### Verifying

Let's try to verify that image.

```
$ scrane -key public.key verify us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","size":1201,"digest":"sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715","annotations":{"author":"jonjohnsonjr"}}
{"mediaType":"application/vnd.docker.distribution.manifest.list.v2+json","size":1201,"digest":"sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715","annotations":{"hello":"world"}}
2021/02/02 10:04:35 Verified OK
```

More readable:
```
$ scrane -key public.key verify us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715 2>/dev/null | jq .
```
```json
{
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "size": 1201,
  "digest": "sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715",
  "annotations": {
    "author": "jonjohnsonjr"
  }
}
{
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "size": 1201,
  "digest": "sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715",
  "annotations": {
    "hello": "world"
  }
}
```


The output is json-lines, each line being a descriptor pointing to the artifact we signed.
Each `-a` flag shows up under `annotations`.
We could easily have multiple annotations per descriptor, as well.

### How does this work?

Let's look at the thing we signed.
It's a manifest list, just an `ubuntu` image I copied from Docker Hub.
```
$ crane manifest us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715 | jq .
```
```json
{
  "manifests": [
    {
      "digest": "sha256:3093096ee188f8ff4531949b8f6115af4747ec1c58858c091c8cb4579c39cc4e",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      },
      "size": 943
    },
    {
      "digest": "sha256:62ff67e3aabbe2d7ea4580207da06644eaba606ecc9cb347e184b7aeb15bc374",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "arm",
        "os": "linux",
        "variant": "v7"
      },
      "size": 943
    },
    {
      "digest": "sha256:de14ad04333bd13b67be947c47b9a61cf2ebd6715f5aae4f8dd59e23c074bde3",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "arm64",
        "os": "linux",
        "variant": "v8"
      },
      "size": 943
    },
    {
      "digest": "sha256:6da906290492c0a8e1d2b2dbe700a5855e702612d01d89fe14534a4c86c23a63",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "ppc64le",
        "os": "linux"
      },
      "size": 943
    },
    {
      "digest": "sha256:856040b95b70ffa8139d18d6086384671474310cb30ec24a8bc1115ab08b6a05",
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "platform": {
        "architecture": "s390x",
        "os": "linux"
      },
      "size": 943
    }
  ],
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "schemaVersion": 2
}
```

When we run `scrane sign`, it prints out an image reference:
```
us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715
```

Note that this looks a lot like the thing we signed, but the tag is `sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715`, which corresponds to the digest of that ubuntu image.
We don't trust anything about this image, it's just a naming convention to help us find signatures.
I'm going to call this thing a **signature index**, for lack of a better name.

Let's look at that signature index.
Similarly to the ubuntu image, it's a manifest list.
Each descriptor here points to an [`application/vnd.oci.descriptor.v1+json`](https://github.com/opencontainers/image-spec/blob/master/descriptor.md).
There is an [annotation](https://github.com/opencontainers/image-spec/blob/master/annotations.md), `dev.ggcr.crane/signature`, that contains a base64-encoded signature.
That string is arbitrary, we'd probably want it to be some OCI standard thing.
We may also need additional annotations here to help clients understand what they need to do, but only as a hint -- nothing in here should be trusted.

```
$ crane manifest us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715 | jq .
```
```json
{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.oci.descriptor.v1+json",
      "size": 208,
      "digest": "sha256:e8762debcae6c97e19b0f27182c8167c1b3db19085b7d23dc0ac03743def6655",
      "annotations": {
        "dev.ggcr.crane/signature": "slSkEyaQxMjZG6i098oJtlLH1L1OxjuT20bOWCoUGUdL9MdUvHwef8RwIle8WMf6EtcDgTFdFvLybGZeCOJxIA=="
      }
    },
    {
      "mediaType": "application/vnd.oci.descriptor.v1+json",
      "size": 200,
      "digest": "sha256:5be45a5f24e923017982b6313b13bcd953911b6841565427868893e0050c59d9",
      "annotations": {
        "dev.ggcr.crane/signature": "JRD8ETJfTUZKFAQe84IgiAVoCE6jqH5KTlHsE0TZoOd87Wa58AYFyBV5EWsHDJ3ooGk2MA9x+qV0SqnxW1dotQ=="
      }
    }
  ]
}
```

The thing that is actually signed is the descriptor, let's look at those:
```
$ crane blob us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:e8762debcae6c97e19b0f27182c8167c1b3db19085b7d23dc0ac03743def6655 | jq .
```
```json
{
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "size": 1201,
  "digest": "sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715",
  "annotations": {
    "author": "jonjohnsonjr"
  }
}
```
```
$ crane blob us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:5be45a5f24e923017982b6313b13bcd953911b6841565427868893e0050c59d9 | jq .
```
```json
{
  "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
  "size": 1201,
  "digest": "sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715",
  "annotations": {
    "hello": "world"
  }
}
```

We _do_ trust these, because they are guarded by a signature.
These point to the original image we signed, but also contain that `annotations` map.
The `annotations` map is where we put any additional metadata that we would like to sign.
It's possible to sign a descriptor with no annotations or many annotations, it doesn't matter.
How those annotations should be interpreted is up to each client and policy.

If you don't trust `scrane verify`, we can do that verification manually with `openssl`.
Let's look at the second descriptor:

```
$ openssl dgst -sha256 -verify public.key \
  -signature <(crane manifest us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715 |
                 jq '.manifests[1].annotations["dev.ggcr.crane/signature"]' -r |
                 base64 --decode) \
  <(crane blob us-west1-docker.pkg.dev/jonjohnson-test/test/ubuntu@sha256:5be45a5f24e923017982b6313b13bcd953911b6841565427868893e0050c59d9)
Verified OK
```

### Try it yourself

I've published these images publicly if you'd like to play with this:

`us-docker.pkg.dev/jonjohnson-test/public/scrane@sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715`

`us-docker.pkg.dev/jonjohnson-test/public/scrane:sha256-703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715`

Here's the public key:

```
-----BEGIN PUBLIC KEY-----
MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBANFTtjZspuz/hmpT6/dcRFZV2dLtilv8
PzM2Xer3/945pqawvtBSWIW41zhkwagSNN/3BOnq1xwjNUZ1qrFSDCkCAwEAAQ==
-----END PUBLIC KEY-----
```

## Caveats and Considerations

### Hiding from the garbage collector

You might expect that having these pointers to the ubuntu image would prevent it from being deleted.
However, because we're storing this metadata as an opaque blob in the registry, most implementations (all, as far as I know) will not parse the content at all.
This means the registry has no idea there is a link between these images, so it's fine for someone else to delete the ubuntu image.

Unfortunately, this means that our signature index _won't_ get cleaned up if you delete the original image.
These will just stick around forever, polluting your tags.
I think that's _just fine_, as you shouldn't ever really want to delete these.
If you do want to delete them, we can have clients know to look for a signature index at these well-known paths  and delete them.
We could also have users specify explicitly where to write and read the signature index for an image, e.g. in a separate sibling repository or just a hard-coded image path.
It's also not unreasonable to have pubsub do a cleanup of the signature index if the original gets deleted.

### Race conditions

There's nothing in this design preventing someone from maliciously overwriting the signature index.
I think that's _fine_, because if your policy requires some signed metadata to exist, it will complain when it does not find what it expects.
However, you can't rely on the registry to truthfully tell you whether or not signatures exist for your image.
We'd need registry support for something like that, or you'd need to resolve the signature index's tag to a digest and pass that along to the policy (doesn't seem too hard).

There are also non-malicious race conditions.
If two clients attempt to append a signature to the same signature index at the same time, we might lose one.
This is a deficit in the registry spec, but we can solve that using normal HTTP semantics via [`ETag`s](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag).
An obvious `ETag` value that should always be returned is the digest of the manifest.
Per [RFC 7232](https://tools.ietf.org/html/rfc7232#section-2.3), we can use `If-Match` and `If-None-Match` 

Before writing a signature index, we need to first do a GET to see if one already exists.

If it exists, we use `If-Match: <ETag>` with the `ETag` header that the registry returned to make sure nothing has modified it since we checked.

If it doesn't exist, we use `If-None-Match: *` to ensure that nothing has created a different signature index before us.

The registry must return a 412 if these preconditions aren't met.

_Aside: this behavior would also help in other areas. E.g. if you want to fan-out multi-platform image construction to multiple machines, you currently have to fan-in somewhere before writing to the registry.
If we could rely on `ETag` semantics, the fan-in could be coordinated with the registry for a given tag, which would simplify the build implementation._

I propose we add this to the distribution spec in some way, since it's already an existing HTTP RFC -- we just need to call it out.

### Client-side coordination

The previous section makes this obvious, but I want to specifically call out that this implementation asks a lot of clients.
This has the benefit of working, today, without changing the registry at all (beyond fixing race conditions), but at the cost of pushing all the complexity down to clients.
I think this is a reasonable trade-off, given that we will need to modify clients to support this _anyway_.

Any implementations that require coordination with the registry are non-starters, in my opinion:

1. Most clients are open source, whereas many registries are closed source.

If we want to land non-trivial changes to the registry protocol, we need to convince other people to do the work.
With client-side changes, we can do most of that work ourselves.

2. Registries are also very stateful.

Any requirements of the registry to store or index new data will likely force registry operators to perform a migration (and often a backfill).
These things can take _years_.

3. Registries are production services.

Rolling out any public-facing changes is a deliciate procedure, and we should not force this upon registry operators without careful consideration.

4. New semantics are unreliable.

The cross-product of client and registry behavior is _enormous_.
Any deviation from docker or Docker Hub can lead to unexpected behavior.
Given the first point, we're going to have many different implementations of whatever we produce in the spec.
Unless that spec is _perfect_, there will likely be slight differences in behavior, which we _don't_ want _at all_ for something like signatures.
(See the vulnerability factory that is JWT.)

The existing registry behavior has been pretty well tested, for years, and we can generally rely on it.
If we build on top of that, we can be pretty confident that things will work.

## Variants

### Direct image reference

Rather than signing a descriptor, we could just have the signature index directly point to what we're signing.

For example:

```json
{
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.docker.distribution.manifest.list.v2+json",
      "size": 1201,
      "digest": "sha256:703218c0465075f4425e58fac086e09e1de5c340b12976ab9eb8ad26615c3715",
      "annotations": {
        "dev.ggcr.crane/signature": "JRD8ETJfTUZKFAQe84IgiAVoCE6jqH5KTlHsE0TZoOd87Wa58AYFyBV5EWsHDJ3ooGk2MA9x+qV0SqnxW1dotQ=="
      }
    }
  ]
}
```

(That signature is invalid, but use your imagination.)

There are a couple drawbacks to this:

1. This will tend to pin the image that we signed, since registries do GC.
2. We can't sign arbitrary metadata as `annotations` anymore unless those annotations are on the image (changes the digest).

One nice thing about this approach is that you could point normal clients at _this_ instead of the image, and they would know how to fetch it.
As part of normal index resolution, we could collect any signatures that we find and use them to enforce our policy.

Unfortunately, a lot of people see this as "changing the digest" of the image, because the top-level digest of what the client first fetches (this signature index) would not match the digest of the image (of course) even though this _points to_ that image, by the correct digest.

### Signed blobs

TODO: Direct, same drawbacks as above
TODO: Indirect, need to make sure we pin the blob so registry doesn't GC

### Simple signature red hat thing

TODO

### More interesting topologies

TODO: Nested signatures

### Pointer analogy

TODO: go interfaces
