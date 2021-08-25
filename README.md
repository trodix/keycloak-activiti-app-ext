# Keycloak Extension for Activiti

This library was created to expand the functionality of keycloak integration within the APS (Activiti App) application.  It includes a similar implementation for core Activiti (Activiti Engine), but the core functional is not delivered with that OOTB application at this time.

The Activiti App delivers SSO capability and that is about it.  The user must already exist and group synchronization may only happen outside of the context of authentication.  Namely over another protocol (LDAP).

This module expands SSO to include user creation and group synchronization.  Group synchronization uses the standard access token for Open ID Connect.  These groups are termed "roles".

## Installation

The installation is simple.  Just include the JAR in the classpath of your Activiti App application.  This is best done by not chaning the `activiti-app.war` file, but instead including it within the classpath using your web container configuration.  For Apache Tomcat, you would add or modify the following context file: `conf/Catalina/localhost/activiti-app.xml`.  Its related contents would be:

```xml
<Context>
        <Resources>
                <PostResources base="${catalina.base}/ext" className="org.apache.catalina.webresources.DirResourceSet" webAppMount="/WEB-INF/lib" readOnly="true" />
        </Resources>
</Context>
```

Notice the use of `PostResources` instead of `PreResources`.  This library needs to be loaded after the web application.  This is the best way to load any other extensions or customization to the Activiti App, including `JavaDelegate` implementations.

## Configuration

The library is highly configurable.  You configure it with properties specified in the `activiti-app.properties` file, which exists somewhere in the root of the classpath.  That is typically in the `lib` folder.  The properties to configure are enumerated in the table below.

### Common

| Property                                       | Default   | Description |
| ---------------------------------------------- | --------- | ----------- |
| `keycloak-ext.ais.enabled`                     | `false`   | Enable AIS integration, overriding and extending the OOTB AIS provider. |
| `keycloak-ext.ootbSecurityConfig.enabled`      | `true`    | Enable OOTB functionality as if this module were not installed.  This adapter operates at priority `0`.  This means it only works if other adapters are disabled (default). |
| `keycloak-ext.default.admins.users`            |           | A default set of administrators to add to the administration role on application startup. |
| `keycloak-ext.clearNewUserDefaultGroups`       | `true`    | When creating a new user, clear any default groups added to that user.  This will not impact existing users. |
| `keycloak-ext.resource.include.regex.patterns` |           | OIDC provides roles in the realm and all permitted clients/resources.  By default all resources are included.  You can limit it with regular expressions with this property. |
| `keycloak-ext.group.format.regex.patterns`     |           | Reformat roles that match the specified regular expressions.  The replacements are specified in another property.  Multiple expressions may be specified by using commas.  Whitespace is not stripped. |
| `keycloak-ext.group.format.regex.replacements` |           | Reformat roles with the specified replacement expressions.  The regular expressions are specified in another property.  Multiple expressions may be specified by using commas.  Whitespace is not stripped. |
| `keycloak-ext.group.include.regex.patterns`    |           | If specified, only the roles that match the specified regular expressions will be considered; otherwise all roles are included. |
| `keycloak-ext.group.exclude.regex.patterns`    |           | If specified, the roles that match the specified regular expressions will be ignored.  This overrides any role explicitly included. |
| `keycloak-ext.syncInternalGroup`               | `false`   | If an internal group with the same name already exists, use that group instead of creating a new one with the same name.  Also register that internal group as external. |

### For Activiti App Only

| Property                                  | Default        | Description |
| ----------------------------------------- | -------------- | ----------- |
| `keycloak-ext.syncGroupAs`                | `organization` | When creating a new group, should it be a functional (`organization`) group or a system (`capability`) group? |
| `keycloak-ext.external.id`                | `ais`            | When creating a new group or registering an internal group as external, use this ID as a prefix to the external group ID. |

### Rare

| Property                                  | Default         | Description |
| ----------------------------------------- | --------------- | ----------- |
| `keycloak-ext.ais.priority`               | `-10`           | The order of configurable adapters to use with the application.  Only the lowest priority enabled adapter will be used.  Values of `1`+ will only load if the OOTB adapter is disabled. |
| `keycloak-ext.group.admins.validate`      | `false`         | Whether or not to validate the existence and capabilities of an administrators group on appliation startup.  This is only applicable for when one is accidently removed and no one has the rights to create one. |
| `keycloak-ext.group.admins.name`          | `admins`        | The name of an administrators group to potentially add and default users on application startup. |
| `keycloak-ext.group.admins.externalId`    | `admins`        | The name of an administrators group to potentially add and default users on application startup. |
| `keycloak-ext.createMissingUser`          | `true`          | Before authentication, check to make sure the user exists as an APS user; if they don't, create the user. |
| `keycloak-ext.createMissingGroup`         | `true`          | Before authorization, check to make sure groups exist for the roles the user claims; if they don't, create the groups. |
| `keycloak-ext.syncGroupAdd`               | `true`          | If the user belongs to a role but not its corresponding group, add the user to the group. |
| `keycloak-ext.syncGroupRemove`            | `true`          | If the user belongs to a group but does not have the corresponding role, remove the user from the group. |

### Untested

| Property                                  | Default         | Description |
| ----------------------------------------- | --------------- | ----------- |
| `keycloak-ext.keycloak.enabled`           | `false`         | Enable Keycloak integration, overriding and extending the OOTB Keycloak provider (*untested*). |
| `keycloak-ext.keycloak.priority`          | `-5`            | The order of configurable adapters to use with the application.  Only the lowest priority enabled adapter will be used.  Values of `1`+ will only load if the OOTB adapter is disabled. |
