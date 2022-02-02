author: Nathan Smith <fulcio@nfsmith.ca>
date: 2022-02-02
---

# RFC-00 An RFC process

At the moment on the Fulcio project we have a lightweight planning process that
roughly involves creating an issue on Github for a bug or enhancement and then
submitting a patch to fix that issue. This works reasonably well for small
changes, but sometimes a larger change requires more upfront discussion and a
clear specification for what the finished change will look like. Additionally
it would be ideal if these important design decision where documented for
future contributors.

## The RFC process

To create an RFC, create a copy the RFC template to a new file

```
cp docs/rfc/_template.md docs/rfc/04-my-rfc.md
```

Prefix your RFC with its number. Increment the number from the latest RFC.
Next, describe in detail the change you're proposing to make. This should
include background information on the problem space so that little prior
knowledge is assumed of the reader.

Once you're happy with your initial draft, submit your RFC as a pull request.
The pull request code review process is used to iterate, discuss and come to a
final conclusion about whether or not the Fulcio project should accept an RFC.

## When to submit an RFC

An RFC should be submitted if any of the following things is true

- Work to implement something will span many pull requests and you want to
  inform maintainers and other contributors about what the final goal of your
work is.
- Your work will change how Fulcio functions in an important way you'd like to
  document for users and contributors

## Conclusions

If the proposed RFC process is followed the following benefits are gained

- Maintainers become aware of larger strategic work that folks would like to
  complete in the Fulcio project as they must perform code review of these
RFC's
- Each large decision is documented in the repository so that future
  contributors can learn about how and why the project got to the point its
currently at. This decision record process can help stop the continual
rehashing of the same topics over and over as well.
