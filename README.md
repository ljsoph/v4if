## v4if

Get minimal info about IPv4 network interfaces on (my) Linux and (my) Windows machines.

**Example**
```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let interfaces = v4if::interfaces()?;

    for interface in interfaces {
        if interface.is_up() && !interface.is_loopback() {
            println!("{interface:#?}");
        }
    }

    Ok(())
}
```
