# Multi-Class Classification in Rspamd

## Overview

Rspamd now supports multi-class classification beyond the traditional binary spam/ham classification. This document describes how to use the new multi-class classification feature.

## Current Status

### Implemented Features

- **New API Endpoint**: `/learn` endpoint that accepts a `Class` header parameter
- **Backward Compatibility**: Existing `/learnspam` and `/learnham` endpoints continue to work
- **Infrastructure**: Core data structures updated to support class names
  - `rspamd_statfile_config` has a new `class_name` field
  - `rspamd_task` has a new `learn_class` field
  - New functions: `rspamd_stat_learn_class()` and `rspamd_learn_task_class()`

### Current Limitations

The current implementation provides the infrastructure for multi-class classification but currently only supports the "spam" and "ham" classes. Full support for arbitrary classes requires additional work in:

1. Configuration parsing to allow defining custom classes in statfile sections
2. Bayes classifier to calculate probabilities for N classes (currently uses binary classification)
3. Backend storage to efficiently track multiple classes per token

## Using the New API

### Learning with the `/learn` Endpoint

To train the classifier with a specific class, use the `/learn` endpoint with the `Class` header:

```bash
# Learn as spam
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: spam" \
  -H "Content-Type: text/plain" \
  --data-binary @message.eml

# Learn as ham
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: ham" \
  -H "Content-Type: text/plain" \
  --data-binary @message.eml
```

### Optional Classifier Parameter

You can optionally specify which classifier to use with the `Classifier` header:

```bash
curl -X POST http://localhost:11334/learn \
  -H "Password: your-password" \
  -H "Class: spam" \
  -H "Classifier: bayes" \
  -H "Content-Type: text/plain" \
  --data-binary @message.eml
```

## Configuration

### Current Configuration Format

The statfile configuration currently supports the traditional `spam` boolean field:

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

### Future Configuration Format

In a future version, you will be able to define custom classes:

```
classifier "bayes" {
  statfile {
    symbol = "BAYES_HAM";
    class = "ham";
  }
  statfile {
    symbol = "BAYES_SPAM";
    class = "spam";
  }
  # Future: support for additional classes
  statfile {
    symbol = "BAYES_PHISHING";
    class = "phishing";
  }
}
```

## Backward Compatibility

All existing functionality is preserved:
- `/learnspam` and `/learnham` endpoints work as before
- Existing configurations with `spam = true/false` continue to work
- The `is_spam` field in `rspamd_statfile_config` is maintained for compatibility

## API Reference

### HTTP Endpoints

#### POST /learn

Learn a message with a specific class.

**Headers:**
- `Password` (required): Authentication password
- `Class` (required): The class name (currently "spam" or "ham")
- `Classifier` (optional): Specific classifier to use

**Request Body:** Email message in RFC822 format

**Response:**
```json
{"success": true}
```

Or on error:
```json
{"error": "error message"}
```

### C API Functions

#### rspamd_stat_learn_class()

```c
rspamd_stat_result_t rspamd_stat_learn_class(
    struct rspamd_task *task,
    const char *class_name,
    lua_State *L,
    const char *classifier,
    unsigned int stage,
    GError **err
);
```

Learn a task for a specific class.

**Parameters:**
- `task`: The task to learn
- `class_name`: Name of the class (e.g., "spam", "ham")
- `L`: Lua state
- `classifier`: Classifier name (NULL for all)
- `stage`: Learning stage
- `err`: Error output parameter

**Returns:** RSPAMD_STAT_PROCESS_OK on success, RSPAMD_STAT_PROCESS_ERROR on failure

#### rspamd_learn_task_class()

```c
gboolean rspamd_learn_task_class(
    struct rspamd_task *task,
    const char *class_name,
    const char *classifier,
    GError **err
);
```

Set up a task for learning with a specific class.

**Parameters:**
- `task`: The task to configure
- `class_name`: Name of the class
- `classifier`: Classifier name (NULL for all)
- `err`: Error output parameter

**Returns:** TRUE on success, FALSE on failure

## Future Work

To fully support arbitrary multi-class classification, the following components need to be extended:

1. **Configuration Parsing**: Add support for `class` field in statfile configuration as an alternative to `spam` boolean
2. **Bayes Classifier**: Implement true multi-class probability calculations (e.g., one-vs-all or softmax)
3. **Token Storage**: Extend backends to efficiently store and retrieve token statistics for multiple classes
4. **Classification Logic**: Update the classification pipeline to handle N classes instead of binary
5. **Lua API**: Extend Lua functions to work with arbitrary class names

## Contributing

If you're interested in implementing full multi-class classification support, please see the implementation plan in the PR description and feel free to contribute!
