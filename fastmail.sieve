require ["fileinto", "reject", "vacation", "notify", "envelope", "body", "relational", "regex", "subaddress", "copy", "mailbox", "mboxmetadata", "servermetadata", "date", "index", "comparator-i;ascii-numeric", "variables", "imap4flags", "editheader", "duplicate", "vacation-seconds"];

### 1. Sieve generated for save-on-SMTP identities
# You do not have any identities with special filing.

### 2. Sieve generated for discard rules
# You do not have any discard rules.

### 3. Sieve generated for spam protection
if not header :matches "X-Spam-Known-Sender" "yes*" {
  if
    allof(
    header :contains "X-Backscatter" "yes",
    not header :matches "X-LinkName" "*"
    )
  {
    fileinto "\\Junk";
    stop;
  }
  if header :value "ge" :comparator "i;ascii-numeric" "X-Spam-score" "5" {
    fileinto "\\Junk";
    stop;
  }
}

### 4. Sieve generated for forwarding rules
# You do not have any forwarding rules.

### 5. Sieve generated for vacation responses
# You do not have vacation responses enabled.

### Custom filing code
# file email into legacy that doesn't contain a modern address
if allof (
  address :is ["To","Cc","Resent-To","X-Delivered-To"] "stuart@testtrack4.com",
  not address :domain :is ["To","Cc"] "stuartpb.com"
){
  fileinto "INBOX.legacy";
  stop;
}

### 6. Sieve generated for calendar preferences
if
  allof(
  header :is "X-ME-Cal-Method" "request",
  not exists "X-ME-Cal-Exists",
  header :contains "X-Spam-Known-Sender" "in-addressbook"
  )
{
  notify :method "addcal";
}
elsif exists "X-ME-Cal-Exists" {
  notify :method "updatecal";
}

### 7. Sieve generated for organise rules
if
  anyof(
  exists "List-Id",
  exists "List-Post",
  exists "List-Unsubscribe"
  )
{
  fileinto "INBOX.Lists";
}

### 8. Sieve generated for pop-link filing
# You have no pop-links filing into special folders.
