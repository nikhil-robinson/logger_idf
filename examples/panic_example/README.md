# Blackbox Logger - Panic Handler Example

Simple example demonstrating the blackbox logger's automatic panic handler.

## How It Works

The library **automatically handles everything internally**:

1. Set `panic_flags` in config
2. Call `blackbox_init()` 
3. That's it! Crashes are automatically logged.

No callbacks, no complex setup required.

## What Gets Logged on Crash

- Crash reason (LoadProhibited, assertion, etc.)
- Stack backtrace  
- CPU register dump
- Memory dump (if enabled)

## Usage

```c
blackbox_config_t config;
blackbox_get_default_config(&config);
config.root_path = "/sdcard/logs";

// Enable panic handler (default already has it enabled)
config.panic_flags = BLACKBOX_PANIC_FLAGS_DEFAULT;

blackbox_init(&config);  // Panic handler automatically registered!
```

## Building

```bash
cd examples/panic_example
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor
```

## Decoding Crash Logs

```bash
python tools/blackbox_decoder.py crash001.blackbox
```

## Panic Flags

| Flag | Description |
|------|-------------|
| `BLACKBOX_PANIC_FLAGS_DEFAULT` | Enabled + backtrace + registers |
| `BLACKBOX_PANIC_FLAGS_ALL` | All features including memory dump |
| `BLACKBOX_PANIC_FLAG_NONE` | Disable panic handler |
