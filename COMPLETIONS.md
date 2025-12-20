# Shell Completions for myc CLI

The `myc` CLI supports shell completions for bash, zsh, fish, and PowerShell. This provides tab completion for commands, subcommands, and options.

## Installation

### Bash

Add the following to your `~/.bashrc`:

```bash
eval "$(myc completions bash)"
```

Then reload your shell or run:
```bash
source ~/.bashrc
```

### Zsh

Add the following to your `~/.zshrc`:

```zsh
eval "$(myc completions zsh)"
```

Then reload your shell or run:
```zsh
source ~/.zshrc
```

### Fish

Add the following to your fish configuration:

```fish
myc completions fish | source
```

To make it persistent, add it to your fish config file:
```fish
echo "myc completions fish | source" >> ~/.config/fish/config.fish
```

### PowerShell

Add the following to your PowerShell profile:

```powershell
Invoke-Expression (& myc completions powershell)
```

To find your PowerShell profile location, run:
```powershell
$PROFILE
```

## Usage

Once installed, you can use tab completion with the `myc` command:

- `myc <TAB>` - Shows available commands
- `myc profile <TAB>` - Shows profile subcommands
- `myc pull --<TAB>` - Shows available options
- `myc completions <TAB>` - Shows available shells

## Generating Completions

You can also generate completions to a file:

```bash
# Generate bash completions to a file
myc completions bash > myc-completions.bash

# Generate with JSON output for programmatic use
myc --json completions bash
```

## Supported Shells

- **bash** - Bourne Again Shell
- **zsh** - Z Shell  
- **fish** - Friendly Interactive Shell
- **powershell** - PowerShell
- **elvish** - Elvish Shell (experimental)

## Troubleshooting

If completions aren't working:

1. Make sure you've reloaded your shell after installation
2. Verify the `myc` binary is in your PATH
3. For bash/zsh, ensure you have completion support enabled
4. Try generating completions manually to test: `myc completions <shell>`

## Examples

```bash
# Install bash completions
eval "$(myc completions bash)"

# Test completions work
myc pro<TAB>  # Should complete to "profile"
myc profile a<TAB>  # Should complete to "add"

# Generate completions for distribution
myc completions bash > completions/myc.bash
myc completions zsh > completions/_myc
myc completions fish > completions/myc.fish
```