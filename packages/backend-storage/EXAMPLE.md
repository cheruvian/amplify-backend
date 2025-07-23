# Storage Access Metadata Example

This example demonstrates how to use the new `access` property to programmatically access storage access rules metadata in your backend CDK files.

## Define Storage with Access Rules

First, define your storage with access rules:

```typescript
// amplify/storage/resource.ts
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
    'admin/*': [allow.groups(['Admin']).to(['read', 'write', 'delete'])],
  }),
});
```

## Access Storage Rules Metadata

Then, in your backend CDK files, you can programmatically access the access rules:

```typescript
// amplify/backend.ts or other CDK files
import { defineBackend } from '@aws-amplify/backend';
import { storage } from './storage/resource.js';
import { PolicyStatement, Effect } from 'aws-cdk-lib/aws-iam';

export const backend = defineBackend({
  storage,
});

// Access specific permissions
const publicAuthPermissions = storage.access['public/*']?.authenticated;
console.log(
  'Authenticated users can access public files with:',
  publicAuthPermissions,
);
// Output: ['get', 'list', 'write', 'delete']

const publicGuestPermissions = storage.access['public/*']?.guest;
console.log(
  'Guest users can access public files with:',
  publicGuestPermissions,
);
// Output: ['get', 'list']

// Check if a specific permission exists
if (storage.access['admin/*']?.groupsAdmin?.includes('write')) {
  console.log('Admin group has write access to admin files');
}

// Iterate over all access rules
Object.entries(storage.access).forEach(([path, rules]) => {
  console.log(`\nPath: ${path}`);
  Object.entries(rules).forEach(([accessType, actions]) => {
    console.log(`  ${accessType}: ${actions.join(', ')}`);
  });
});
// Output:
// Path: public/*
//   authenticated: get, list, write, delete
//   guest: get, list
// Path: protected/*
//   entityidentity: get, list, write, delete
// Path: admin/*
//   groupsAdmin: get, list, write, delete

// Use access metadata to create conditional IAM policies
const customPolicyStatements: PolicyStatement[] = [];

// Only create admin policies if admin access is defined
if (storage.access['admin/*']) {
  customPolicyStatements.push(
    new PolicyStatement({
      effect: Effect.ALLOW,
      actions: ['s3:GetObjectVersion'],
      resources: [`${storage.resources.bucket.bucketArn}/admin/*`],
    }),
  );
}

// Add CloudTrail logging for paths with write access
Object.entries(storage.access).forEach(([path, rules]) => {
  const hasWriteAccess = Object.values(rules).some((actions) =>
    actions.includes('write'),
  );

  if (hasWriteAccess) {
    console.log(`Enabling audit logging for write operations on: ${path}`);
    // Add CloudTrail or other monitoring configuration here
  }
});
```

## Use Cases

This feature enables several powerful use cases:

### 1. Conditional Policy Creation

```typescript
// Only add encryption policies for sensitive paths
if (storage.access['sensitive/*']) {
  // Add KMS encryption requirements
}
```

### 2. Access Validation

```typescript
// Validate that critical paths have proper access controls
const criticalPaths = ['admin/*', 'config/*'];
criticalPaths.forEach((path) => {
  if (!storage.access[path]) {
    throw new Error(`Missing access rules for critical path: ${path}`);
  }
});
```

### 3. Monitoring Configuration

```typescript
// Set up different monitoring for different access levels
Object.entries(storage.access).forEach(([path, rules]) => {
  const isPublic = 'guest' in rules;
  const hasDeleteAccess = Object.values(rules).some((actions) =>
    actions.includes('delete'),
  );

  if (isPublic && hasDeleteAccess) {
    console.log(`⚠️  Warning: Public path ${path} allows delete operations`);
  }
});
```

### 4. Documentation Generation

```typescript
// Generate access documentation
function generateAccessReport() {
  const report = Object.entries(storage.access).map(([path, rules]) => {
    const accessTypes = Object.keys(rules);
    const maxActions = Math.max(
      ...Object.values(rules).map((actions) => actions.length),
    );

    return {
      path,
      accessTypes: accessTypes.length,
      maxPermissions: maxActions,
      isPublic: accessTypes.includes('guest'),
    };
  });

  return report;
}
```

## Type Safety

The `access` property returns a `StorageAccessDefinitionOutput` type that provides full type safety:

```typescript
import { StorageAccessDefinitionOutput } from '@aws-amplify/backend-storage';

// Type-safe access to storage rules
const accessRules: StorageAccessDefinitionOutput = storage.access;

// TypeScript will provide autocomplete and type checking
const publicRules = accessRules['public/*'];
if (publicRules?.authenticated) {
  // TypeScript knows this is InternalStorageAction[]
  const hasReadAccess = publicRules.authenticated.includes('get');
}
```
