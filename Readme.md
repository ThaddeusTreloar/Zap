# Zap

Compress and/or encrypt folders fast. Like, really fast.
or as some say... **blazingly** fast.

## Installation

To install Zap, run the following command from the project root:
`cargo install --path .`

## Usage

### In order to **compress** a folder with Zap, run:

`zap archive [INPUT] [OPTIONS]` Eg:

```
zap archive /path/to/dir -ce
```

Using `zap archive --help` will list the available options for encryption and compression.

### In order to **decompress** a Zap archive

`zap extract [ARCHIVE]`

Where the `[ARCHIVE]` is the path to the file which you want to extract.

Using `zap archive --help` will list the available options for encryption and compression.

```
zap extract ./dir.zap
```

### In order to **list** the contents of a Zap archive

`zap list [ARCHIVE]`

*coming soon*

## License

This project is licensed under the LGPL v3.

See [LICENSE.md](/LICENSE.md) file for details.

![LGPL v3 Logo](https://www.gnu.org/graphics/lgplv3-with-text-154x68.png)

Note that Zap is still alpha software and is bound to change core features until version 0.5.0
