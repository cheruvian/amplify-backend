import { beforeEach, describe, it, mock } from 'node:test';
import assert from 'node:assert';
import { roleAccessBuilder } from './access_builder.js';
import {
  ConstructContainer,
  ConstructFactoryGetInstanceProps,
  ResourceAccessAcceptorFactory,
  ResourceProvider,
} from '@aws-amplify/plugin-types';
import { CfnUserPoolGroup } from 'aws-cdk-lib/aws-cognito';
import { Role } from 'aws-cdk-lib/aws-iam';

void describe('storageAccessBuilder', () => {
  const resourceAccessAcceptorMock = mock.fn();
  const group1AccessAcceptorMock = mock.fn();
  const group2AccessAcceptorMock = mock.fn();

  const getResourceAccessAcceptorMock = mock.fn((roleName: string) => {
    switch (roleName) {
      case 'group1Name':
        return group1AccessAcceptorMock;
      case 'group2Name':
        return group2AccessAcceptorMock;
      default:
        return resourceAccessAcceptorMock;
    }
  });

  const getConstructFactoryMock = mock.fn(
    // this lets us get proper typing on the mock args
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    <T extends ResourceProvider>(_: string) => ({
      getInstance: () =>
        ({
          resources: {
            groups: {}, // Empty groups object for existing tests
          },
          getResourceAccessAcceptor: getResourceAccessAcceptorMock,
        }) as unknown as T,
    }),
  );
  const stubGetInstanceProps: ConstructFactoryGetInstanceProps = {
    constructContainer: {
      getConstructFactory: getConstructFactoryMock,
    } as unknown as ConstructContainer,
  } as unknown as ConstructFactoryGetInstanceProps;

  beforeEach(() => {
    getResourceAccessAcceptorMock.mock.resetCalls();
    getConstructFactoryMock.mock.resetCalls();
    resourceAccessAcceptorMock.mock.resetCalls();
  });

  void it('builds storage access definition for authenticated role', () => {
    const accessDefinition = roleAccessBuilder.authenticated.to([
      'read',
      'write',
      'delete',
    ]);
    assert.deepStrictEqual(accessDefinition.actions, [
      'read',
      'write',
      'delete',
    ]);
    assert.equal(accessDefinition.idSubstitution, '*');
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
    assert.equal(
      getConstructFactoryMock.mock.calls[0].arguments[0],
      'AuthResources',
    );
    assert.equal(
      getResourceAccessAcceptorMock.mock.calls[0].arguments[0],
      'authenticatedUserIamRole',
    );
  });
  void it('builds storage access definition for guest role', () => {
    const accessDefinition = roleAccessBuilder.guest.to([
      'read',
      'write',
      'delete',
    ]);
    assert.deepStrictEqual(accessDefinition.actions, [
      'read',
      'write',
      'delete',
    ]);
    assert.equal(accessDefinition.idSubstitution, '*');
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
    assert.equal(
      getConstructFactoryMock.mock.calls[0].arguments[0],
      'AuthResources',
    );
    assert.equal(
      getResourceAccessAcceptorMock.mock.calls[0].arguments[0],
      'unauthenticatedUserIamRole',
    );
  });
  void it('builds storage access definition for IdP identity', () => {
    const accessDefinition = roleAccessBuilder
      .entity('identity')
      .to(['read', 'write', 'delete']);
    assert.deepStrictEqual(accessDefinition.actions, [
      'read',
      'write',
      'delete',
    ]);
    assert.equal(
      accessDefinition.idSubstitution,
      '${cognito-identity.amazonaws.com:sub}',
    );
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
    assert.equal(
      getConstructFactoryMock.mock.calls[0].arguments[0],
      'AuthResources',
    );
    assert.equal(
      getResourceAccessAcceptorMock.mock.calls[0].arguments[0],
      'authenticatedUserIamRole',
    );
  });

  void it('builds storage access definition for resources', () => {
    const accessDefinition = roleAccessBuilder
      .resource({
        getInstance: () =>
          ({
            getResourceAccessAcceptor: getResourceAccessAcceptorMock,
          }) as unknown as ResourceProvider & ResourceAccessAcceptorFactory,
      })
      .to(['read', 'write', 'delete']);

    assert.deepStrictEqual(accessDefinition.actions, [
      'read',
      'write',
      'delete',
    ]);
    assert.equal(accessDefinition.idSubstitution, '*');
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
  });

  void it('builds storage access definition for groups with wildcard access', () => {
    const accessDefinition = roleAccessBuilder
      .groups(['group1Name', 'group2Name'])
      .to(['read', 'write']);

    assert.deepStrictEqual(accessDefinition.actions, ['read', 'write']);
    // Groups get wildcard access (no entity substitution)
    assert.equal(accessDefinition.idSubstitution, '*');
    // Groups use the authenticated role
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
    // Should include group conditions for both groups
    assert.deepStrictEqual(accessDefinition.groupConditions, [
      'group1Name',
      'group2Name',
    ]);
  });

  void it('builds storage access definition for entity access only', () => {
    const accessDefinition = roleAccessBuilder
      .entity('identity')
      .to(['read', 'write']);

    assert.deepStrictEqual(accessDefinition.actions, ['read', 'write']);
    // Entity access respects identity substitution
    assert.equal(
      accessDefinition.idSubstitution,
      '${cognito-identity.amazonaws.com:sub}',
    );
    // Uses authenticated role
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
    // No group conditions for entity-only access
    assert.equal(accessDefinition.groupConditions, undefined);
  });

  void it('builds storage access definition for entity access restricted to groups', () => {
    const accessDefinition = roleAccessBuilder
      .entity('identity')
      .inGroups(['Admins', 'Moderators'])
      .to(['read', 'write', 'delete']);

    assert.deepStrictEqual(accessDefinition.actions, [
      'read',
      'write',
      'delete',
    ]);
    // Entity access with groups still respects identity substitution
    assert.equal(
      accessDefinition.idSubstitution,
      '${cognito-identity.amazonaws.com:sub}',
    );
    // Uses authenticated role
    assert.deepStrictEqual(
      accessDefinition.getResourceAccessAcceptors.map(
        (getResourceAccessAcceptor) =>
          getResourceAccessAcceptor(stubGetInstanceProps),
      ),
      [resourceAccessAcceptorMock],
    );
    // Should include group conditions
    assert.deepStrictEqual(accessDefinition.groupConditions, [
      'Admins',
      'Moderators',
    ]);
  });

  void it('throws error when groups have dedicated roles assigned', () => {
    // Mock auth construct with groups that have roles
    const authResourceAccessAcceptorMock = {
      identifier: 'authenticatedResourceAccessAcceptor',
      acceptResourceAccess: mock.fn(),
    };

    const mockAuthConstruct = {
      resources: {
        groups: {
          AdminGroup: {
            cfnUserGroup: {} as CfnUserPoolGroup,
            role: {} as Role, // This group has a role assigned - should trigger error
          },
          UserGroup: {
            cfnUserGroup: {} as CfnUserPoolGroup,
            // This group has no role - would be fine
          },
        },
      },
      getResourceAccessAcceptor: () => authResourceAccessAcceptorMock,
    };

    const mockConstructContainer = {
      getConstructFactory: () => ({
        getInstance: () => mockAuthConstruct,
      }),
    };

    const stubGetInstancePropsWithGroupRoles = {
      constructContainer: mockConstructContainer,
    } as unknown as ConstructFactoryGetInstanceProps;

    // Test groups() method with group that has role
    assert.throws(
      () => {
        const accessDefinition = roleAccessBuilder
          .groups(['AdminGroup'])
          .to(['read', 'write']);

        // Trigger the validation by calling the resource access acceptor
        accessDefinition.getResourceAccessAcceptors[0](
          stubGetInstancePropsWithGroupRoles,
        );
      },
      {
        name: 'IncompatibleGroupRolesError',
        message:
          'Groups [AdminGroup] have dedicated IAM roles assigned, which is incompatible with conditional storage access.',
      },
    );

    // Test entity().inGroups() method with group that has role
    assert.throws(
      () => {
        const accessDefinition = roleAccessBuilder
          .entity('identity')
          .inGroups(['AdminGroup'])
          .to(['read', 'write']);

        // Trigger the validation by calling the resource access acceptor
        accessDefinition.getResourceAccessAcceptors[0](
          stubGetInstancePropsWithGroupRoles,
        );
      },
      {
        name: 'IncompatibleGroupRolesError',
        message:
          'Groups [AdminGroup] have dedicated IAM roles assigned, which is incompatible with conditional storage access.',
      },
    );

    // Test that groups without roles work fine
    assert.doesNotThrow(() => {
      const accessDefinition = roleAccessBuilder
        .groups(['UserGroup'])
        .to(['read', 'write']);

      // This should not throw since UserGroup has no role
      accessDefinition.getResourceAccessAcceptors[0](
        stubGetInstancePropsWithGroupRoles,
      );
    });
  });
});
