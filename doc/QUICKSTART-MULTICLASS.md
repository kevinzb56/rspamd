# Quick Start: Multi-Class Classification API

## Overview

Rspamd now supports a more flexible learning API that uses class names instead of separate endpoints for spam and ham. This provides a foundation for future multi-class classification support.

## Basic Usage

### Using the New `/learn` Endpoint

Instead of using separate `/learnspam` and `/learnham` endpoints, you can now use a single `/learn` endpoint with a `Class` header:

```bash
# Learn a message as spam
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: spam" \
  -H "Content-Type: text/plain" \
  --data-binary @spam-message.eml

# Learn a message as ham
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: ham" \
  -H "Content-Type: text/plain" \
  --data-binary @ham-message.eml
```

### Backward Compatibility

The old endpoints still work exactly as before:

```bash
# Old way - still works
curl -X POST http://localhost:11334/learnspam \
  -H "Password: your-password" \
  --data-binary @spam-message.eml

curl -X POST http://localhost:11334/learnham \
  -H "Password: your-password" \
  --data-binary @ham-message.eml
```

## Advantages of the New API

1. **Single endpoint**: One URL to remember instead of two
2. **Clear intent**: The class name explicitly states what you're learning
3. **Extensible**: Designed to support additional classes in the future
4. **RESTful**: Follows REST principles with headers for parameters

## Common Use Cases

### Training from a Mail Directory

```bash
# Learn all messages in spam directory as spam
for msg in /path/to/spam/*.eml; do
  curl -X POST http://localhost:11334/learn \
    -H "Password: your-password" \
    -H "Class: spam" \
    --data-binary "@$msg"
done

# Learn all messages in ham directory as ham
for msg in /path/to/ham/*.eml; do
  curl -X POST http://localhost:11334/learn \
    -H "Password: your-password" \
    -H "Class: ham" \
    --data-binary "@$msg"
done
```

### Using rspamc Client

The `rspamc` command-line client can also be used (existing commands):

```bash
# Using rspamc
rspamc learn_spam spam-message.eml
rspamc learn_ham ham-message.eml
```

### Python Example

```python
import requests

def learn_message(message_path, class_name, password="q1"):
    """Learn a message with the specified class"""
    url = "http://localhost:11334/learn"
    headers = {
        "Password": password,
        "Class": class_name,
        "Content-Type": "text/plain"
    }
    
    with open(message_path, 'rb') as f:
        response = requests.post(url, headers=headers, data=f)
    
    return response.json()

# Usage
result = learn_message("spam-message.eml", "spam")
print(result)  # {"success": true}
```

## Error Handling

### Invalid Class Name

Currently, only "spam" and "ham" classes are supported:

```bash
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: phishing" \
  --data-binary @message.eml

# Response:
# {"error": "Unknown class 'phishing'. Currently only 'spam' and 'ham' are supported."}
```

### Missing Class Header

```bash
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  --data-binary @message.eml

# Response:
# {"error": "Class header is required for /learn endpoint"}
```

## Configuration

No configuration changes are needed! The new endpoint works with your existing Rspamd configuration.

Your current classifier configuration in `statistic.conf` or `local.d/classifier-bayes.conf`:

```
classifier "bayes" {
  statfile {
    symbol = "BAYES_HAM";
    spam = false;
  }
  statfile {
    symbol = "BAYES_SPAM";
    spam = true;
  }
}
```

This configuration automatically works with both old and new endpoints.

## Testing Your Setup

Use the provided test script to verify the new API:

```bash
cd /path/to/rspamd
python3 test/functional/test_multiclass_api.py
```

Or test manually:

```bash
# Create a test message
cat > test-message.eml << 'EOF'
From: sender@example.com
To: recipient@example.com
Subject: Test message
Date: Mon, 11 Nov 2024 10:00:00 +0000

This is a test message.
EOF

# Learn it as spam
curl -v -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: spam" \
  --data-binary @test-message.eml

# Expected response:
# HTTP/1.1 200 OK
# {"success": true}
```

## Migration Guide

### If You're Using Custom Scripts

If you have scripts that use `/learnspam` and `/learnham`:

**Option 1: Keep using old endpoints** - They still work, no changes needed.

**Option 2: Update to new endpoint** - More flexible for future features:

```bash
# Old
curl -X POST http://localhost:11334/learnspam -H "Password: $PWD" --data-binary @msg

# New
curl -X POST http://localhost:11334/learn -H "Password: $PWD" -H "Class: spam" --data-binary @msg
```

### If You're Using rspamc

No changes needed! `rspamc learn_spam` and `rspamc learn_ham` continue to work.

## Troubleshooting

### "Connection refused" error
- Ensure Rspamd controller is running
- Check the port (default: 11334)
- Verify firewall settings

### "Unauthorized" error
- Check your password
- Verify it matches the `password` or `enable_password` in `worker-controller.inc`

### "Empty body is not permitted"
- Ensure you're sending the message content
- Use `--data-binary` with curl, not `--data`
- Check file exists and is readable

## Next Steps

- Read the full documentation: `doc/multi-class-classification.md`
- See implementation details: `MULTICLASS_IMPLEMENTATION.md`
- Review example configuration: `conf/statistic-multiclass.conf.example`
- Contribute to full multi-class support!

## Questions?

For issues or questions:
1. Check Rspamd logs: `/var/log/rspamd/rspamd.log`
2. Review documentation in `doc/` directory
3. Open an issue on GitHub

## Current Limitations

- Only "spam" and "ham" classes are currently supported
- Additional classes require extension of the Bayes classifier (see implementation docs)
- Configuration still uses `spam = true/false` boolean (future versions will support `class = "name"`)

Despite these limitations, the new API provides a better foundation for learning and is ready for production use with spam/ham classification!
