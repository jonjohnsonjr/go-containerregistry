# crane examples

TODO: stat blobs (descriptor), upload blobs

## simple debugging

### `manifest`

Print the manifest for the `ubuntu` image.

```
$ crane manifest ubuntu
```

Print a specific platform's manifest from an index:

```
$ crane manifest --platform=linux/amd64 ubuntu:latest
```

Print the manifest at a specific digest:

```
$ crane manifest ubuntu@<TODO>
```

### `config`

Print the config blob for the `ubuntu` image:

```
$ crane config ubuntu
```

This uses the default `linux/amd64` image, because an index can't have a config.

You can override the platform with `--platform` or by specifying a digest:

```
$ crane config ubuntu@<TODO>
```

### `ls`

TODO: listing proposal
TODO: gcrane

### `catalog`

TODO: deprecated, listing proposal

### `digest`

TODO: index vs manifest vs schema 1
TODO: --json to produce a descriptor

### `blob`

TODO: explain convention

### `auth`

TODO: simple debugging, meta-helper, auth README

### `validate`

TODO: ensure integrity

### `version`

TODO: help me help you debug

### flags

#### `--verbose`

#### `--insecure`

## moving things around

TODO: caveats around more general purpose abstractions like skopeo

### `copy`
### `pull`
### `push`

## mutations

### `delete`

TODO: untag vs digest
TODO: dockerhub support

### `tag`

### `append`

Append a layer tarball `layer.tar` to `$OLD_IMAGE`, pushing it as `$NEW_IMAGE`:

```
$ crane append -f layer.tar -b $OLD_IMAGE -t $NEW_IMAGE
```

Append multiple layers:

```
$ crane append -f layer_1.tar -f layer_2.tar -b $OLD_IMAGE -t $NEW_IMAGE
```

Append the contents of a directory `some-dir/` as a layer:

```
$ crane append -f <(tar -c some-dir/ -f -) -t $NEW_IMAGE
```

Same as above, but with no existing image, just as a single-layer image:

```
$ crane append -f <(tar -c some-dir/ -f -) -t $NEW_IMAGE
```

### `export`

Look at the filesystem entries for `$IMAGE`:

```
$ crane export $IMAGE - | tar -tvf -
```

Look for the existence of a particular file:

```
$ crane export $IMAGE - | tar -tvf - | grep etc/os-release
```

Look at the contents of a particular file:

```
$ crane export $IMAGE - | tar -Oxf - etc/os-release
```

Flatten an image into a single layer:

```
# TODO: Loses the config file from $IMAGE, need to rebase this :/
$ crane append -f <(crane export $IMAGE -) -t $NEW_IMAGE
```

### `rebase`
