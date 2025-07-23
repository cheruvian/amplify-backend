# @aws-amplify/backend-storage

Backend storage construct for AWS Amplify.

## Installation

```bash
npm install @aws-amplify/backend-storage
```

## Usage

```typescript
import { defineStorage } from '@aws-amplify/backend-storage';

export const storage = defineStorage({
  name: 'myProjectFiles',
  access: (allow) => ({
    'public/*': [
      allow.guest.to(['read']),
      allow.authenticated.to(['read', 'write']),
    ],
    'protected/{entity_id}/*': [
      allow.entity('identity').to(['read', 'write', 'delete']),
    ],
  }),
});
```

## Accessing Storage Access Rules Metadata

You can programmatically access the storage access rules metadata in your backend CDK files using the `access` property:

```typescript
// In your backend.ts or other CDK files
import { storage } from './storage/resource.js';
import { PolicyStatement } from 'aws-cdk-lib/aws-iam';

// Access permissions for a specific path
const publicPermissions = storage.access['public/*']?.authenticated;
console.log('Authenticated users can:', publicPermissions); // ['get', 'list', 'write', 'delete']

const guestPermissions = storage.access['public/*']?.guest;
console.log('Guest users can:', guestPermissions); // ['get', 'list']

// Access all rules for a path
const allPublicRules = storage.access['public/*'];
console.log('All public rules:', allPublicRules);

// Iterate over all access rules
Object.entries(storage.access).forEach(([path, rules]) => {
  console.log(`Path: ${path}`);
  Object.entries(rules).forEach(([accessType, actions]) => {
    console.log(`  ${accessType}: ${actions.join(', ')}`);
  });
});

// Use access metadata to create custom IAM policies
if (storage.access['private/*']?.authenticated?.includes('write')) {
  // Create additional IAM policy statements based on access rules
  const customPolicy = new PolicyStatement({
    actions: ['s3:PutObjectAcl'],
    resources: [`${storage.resources.bucket.bucketArn}/private/*`],
  });
}
```

This feature allows you to:

- Inspect access rules programmatically
- Create conditional logic based on defined permissions
- Generate additional IAM policies that align with your access rules
- Debug and validate your access configuration

The `access` property returns a `StorageAccessDefinitionOutput` object with the following structure:

```typescript
{
  [path: string]: {
    [accessType: string]: InternalStorageAction[]
  }
}
```

Where:

- `path` is the storage path (e.g., `'public/*'`, `'protected/*'`)
- `accessType` is the type of access (`'authenticated'`, `'guest'`, `'groups{GroupName}'`, `'entity{EntityId}'`, etc.)
- `InternalStorageAction[]` is an array of allowed actions (`'get'`, `'list'`, `'write'`, `'delete'`)
