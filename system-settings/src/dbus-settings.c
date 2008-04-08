/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <NetworkManager.h>
#include <nm-connection.h>
#include <dbus/dbus.h>
#include <string.h>

#include <nm-setting-connection.h>

#include "nm-dbus-glib-types.h"
#include "dbus-settings.h"
#include "nm-system-config-interface.h"
#include "nm-utils.h"

static void exported_connection_get_secrets (NMExportedConnection *connection,
                                             const gchar *setting_name,
                                             const gchar **hints,
                                             gboolean request_new,
                                             DBusGMethodInvocation *context);

G_DEFINE_TYPE (NMSysconfigExportedConnection, nm_sysconfig_exported_connection, NM_TYPE_EXPORTED_CONNECTION);

/*
 * NMSysconfigExportedConnection
 */

static void
check_for_secrets (gpointer key, gpointer data, gpointer user_data)
{
	gboolean *have_secrets = (gboolean *) user_data;

	if (*have_secrets)
		return;

	*have_secrets = g_hash_table_size ((GHashTable *) data) ? TRUE : FALSE;
}

static void
exported_connection_get_secrets (NMExportedConnection *sys_connection,
				 const gchar *setting_name,
				 const gchar **hints,
				 gboolean request_new,
				 DBusGMethodInvocation *context)
{
	NMConnection *connection;
	GError *error = NULL;
	NMSettingConnection *s_con;
	NMSetting *setting;
	GHashTable *settings = NULL;
	NMSystemConfigInterface *plugin;
	gboolean have_secrets = FALSE;

	connection = nm_exported_connection_get_connection (sys_connection);

	g_return_if_fail (NM_IS_CONNECTION (connection));
	g_return_if_fail (setting_name != NULL);

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have requested setting '%s'.",
		             __FILE__, __LINE__, setting_name);
		goto error;
	}

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection,
												   NM_TYPE_SETTING_CONNECTION));
	if (!s_con || !s_con->id || !strlen (s_con->id) || !s_con->type) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection didn't have required '"
		             NM_SETTING_CONNECTION_SETTING_NAME
		             "' setting , or the connection name was invalid.",
		             __FILE__, __LINE__);
		goto error;
	}

	plugin = g_object_get_data (G_OBJECT (connection), NM_SS_PLUGIN_TAG);
	if (!plugin) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection had no plugin to ask for secrets.",
		             __FILE__, __LINE__);
		goto error;
	}

	settings = nm_system_config_interface_get_secrets (plugin, connection, setting);
	if (!settings || (g_hash_table_size (settings) == 0)) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Connection's plugin did not return a secrets hash.",
		             __FILE__, __LINE__);
		goto error;
	}

	g_hash_table_foreach (settings, check_for_secrets, &have_secrets);
	if (!have_secrets) {
		g_set_error (&error, NM_SETTINGS_ERROR, 1,
		             "%s.%d - Secrets were found for setting '%s' but none"
		             " were valid.", __FILE__, __LINE__, setting_name);
		goto error;
	} else {
		dbus_g_method_return (context, settings);
	}

	g_hash_table_destroy (settings);
	return;

error:
	if (settings)
		g_hash_table_destroy (settings);

	g_warning (error->message);
	dbus_g_method_return_error (context, error);
	g_error_free (error);
}

static void
nm_sysconfig_exported_connection_finalize (GObject *object)
{
	G_OBJECT_CLASS (nm_sysconfig_exported_connection_parent_class)->finalize (object);
}

static void
nm_sysconfig_exported_connection_class_init (NMSysconfigExportedConnectionClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);
	NMExportedConnectionClass *connection = NM_EXPORTED_CONNECTION_CLASS (class);

	object_class->finalize = nm_sysconfig_exported_connection_finalize;

	connection->get_secrets = exported_connection_get_secrets;
}

static void
nm_sysconfig_exported_connection_init (NMSysconfigExportedConnection *sysconfig_exported_connection)
{
}

NMSysconfigExportedConnection *
nm_sysconfig_exported_connection_new (NMConnection *connection,
                                      DBusGConnection *g_conn)
{
	NMSysconfigExportedConnection *exported;

	exported = g_object_new (NM_TYPE_SYSCONFIG_EXPORTED_CONNECTION,
	                         NM_EXPORTED_CONNECTION_CONNECTION, connection,
	                         NULL);

	nm_exported_connection_register_object (NM_EXPORTED_CONNECTION (exported),
	                                        NM_CONNECTION_SCOPE_SYSTEM,
	                                        g_conn);

	return exported;
}

/*
 * NMSettings
 */

#include "nm-settings-system-glue.h"

typedef struct {
	GSList *connections;
	GHashTable *unmanaged_devices;
} NMSysconfigSettingsPrivate;

G_DEFINE_TYPE (NMSysconfigSettings, nm_sysconfig_settings, NM_TYPE_SETTINGS);

#define NM_SYSCONFIG_SETTINGS_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SYSCONFIG_SETTINGS, NMSysconfigSettingsPrivate))

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_UNMANAGED_DEVICES,

	LAST_PROP
};

static GPtrArray *
list_connections (NMSettings *settings)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (settings);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GPtrArray *connections;
	GSList *iter;

	connections = g_ptr_array_new ();
	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (iter->data);
		NMConnection *connection;
		char *path;

		connection = nm_exported_connection_get_connection (exported);
		path = g_strdup (nm_connection_get_path (connection));
		if (path)
			g_ptr_array_add (connections, path);
	}
	
	/* Return a list of strings with paths to connection settings objects */
	return connections;
}

static void
settings_finalize (GObject *object)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	if (priv->connections) {
		g_slist_foreach (priv->connections, (GFunc) g_object_unref, NULL);
		g_slist_free (priv->connections);
		priv->connections = NULL;
	}

	g_hash_table_destroy (priv->unmanaged_devices);

	G_OBJECT_CLASS (nm_sysconfig_settings_parent_class)->finalize (object);
}

static void
add_one_unmanaged_device (gpointer key, gpointer data, gpointer user_data)
{
	GPtrArray *devices = (GPtrArray *) user_data;

	g_ptr_array_add (devices, g_strdup (key));	
}

static char*
uscore_to_wincaps (const char *uscore)
{
	const char *p;
	GString *str;
	gboolean last_was_uscore;

	last_was_uscore = TRUE;
  
	str = g_string_new (NULL);
	p = uscore;
	while (p && *p) {
		if (*p == '-' || *p == '_')
			last_was_uscore = TRUE;
		else {
			if (last_was_uscore) {
				g_string_append_c (str, g_ascii_toupper (*p));
				last_was_uscore = FALSE;
			} else
				g_string_append_c (str, *p);
		}
		++p;
	}

	return g_string_free (str, FALSE);
}

static void
notify (GObject *object, GParamSpec *pspec)
{
	GValue *value;
	GHashTable *hash;

	value = g_slice_new0 (GValue);
	hash = g_hash_table_new_full (g_str_hash, g_str_equal, (GDestroyNotify) g_free, NULL);

	g_value_init (value, pspec->value_type);
	g_object_get_property (object, pspec->name, value);
	g_hash_table_insert (hash, uscore_to_wincaps (pspec->name), value);
	g_signal_emit (object, signals[PROPERTIES_CHANGED], 0, hash);
	g_hash_table_destroy (hash);
	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GPtrArray *
get_unmanaged_devices (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	GPtrArray *devices;

 	devices = g_ptr_array_sized_new (3);
	g_hash_table_foreach (priv->unmanaged_devices, (GHFunc) add_one_unmanaged_device, devices);
	return devices;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMSysconfigSettings *self = NM_SYSCONFIG_SETTINGS (object);

	switch (prop_id) {
	case PROP_UNMANAGED_DEVICES:
		g_value_take_boxed (value, get_unmanaged_devices (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_sysconfig_settings_class_init (NMSysconfigSettingsClass *class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (class);	
	NMSettingsClass *settings_class = NM_SETTINGS_CLASS (class);
	
	g_type_class_add_private (settings_class, sizeof (NMSysconfigSettingsPrivate));

	/* virtual methods */
	object_class->notify = notify;
	object_class->get_property = get_property;
	object_class->finalize = settings_finalize;
	settings_class->list_connections = list_connections;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_UNMANAGED_DEVICES,
		 g_param_spec_boxed (NM_SYSCONFIG_SETTINGS_UNMANAGED_DEVICES,
							 "Unamanged devices",
							 "Unmanaged devices",
							 DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
							 G_PARAM_READABLE));

	/* signals */
	signals[PROPERTIES_CHANGED] = 
	                g_signal_new ("properties-changed",
	                              G_OBJECT_CLASS_TYPE (object_class),
	                              G_SIGNAL_RUN_FIRST,
	                              G_STRUCT_OFFSET (NMSysconfigSettingsClass, properties_changed),
	                              NULL, NULL,
	                              g_cclosure_marshal_VOID__BOXED,
	                              G_TYPE_NONE, 1, DBUS_TYPE_G_MAP_OF_VARIANT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (settings_class),
	                                 &dbus_glib_nm_settings_system_object_info);
}

static void
nm_sysconfig_settings_init (NMSysconfigSettings *self)
{
	NMSysconfigSettingsPrivate *priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	priv->unmanaged_devices = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
}

NMSysconfigSettings *
nm_sysconfig_settings_new (DBusGConnection *g_conn)
{
	NMSysconfigSettings *settings;

	settings = g_object_new (nm_sysconfig_settings_get_type (), NULL);
	dbus_g_connection_register_g_object (g_conn, NM_DBUS_PATH_SETTINGS, G_OBJECT (settings));
	return settings;
}

void
nm_sysconfig_settings_add_connection (NMSysconfigSettings *self,
                                      NMConnection *connection,
                                      DBusGConnection *g_connection)
{
	NMSysconfigSettingsPrivate *priv;
	NMSysconfigExportedConnection *exported;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	exported = nm_sysconfig_exported_connection_new (connection, g_connection);
	if (!exported) {
		g_warning ("%s: couldn't export the connection!", __func__);
		return;
	}

	priv->connections = g_slist_append (priv->connections, exported);

	nm_settings_signal_new_connection (NM_SETTINGS (self),
	                                   NM_EXPORTED_CONNECTION (exported));
}

static void
remove_connection (NMSysconfigSettings *self,
                   NMConnection *connection)
{
	NMSysconfigSettingsPrivate *priv;
	GSList *iter;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMSysconfigExportedConnection *item = NM_SYSCONFIG_EXPORTED_CONNECTION (iter->data);
		NMExportedConnection *exported = NM_EXPORTED_CONNECTION (item);
		NMConnection *wrapped;

		wrapped = nm_exported_connection_get_connection (exported);

		if (wrapped == connection) {
			priv->connections = g_slist_remove_link (priv->connections, iter);
			nm_exported_connection_signal_removed (exported);
			g_object_unref (item);
			g_slist_free (iter);
			break;
		}
	}
}

void
nm_sysconfig_settings_remove_connection (NMSysconfigSettings *settings,
                                         NMConnection *connection)
{
	remove_connection (settings, connection);
}

void
nm_sysconfig_settings_update_connection (NMSysconfigSettings *self,
                                         NMConnection *connection)
{
	NMSysconfigSettingsPrivate *priv;
	GHashTable *hash;
	GSList *iter;
	NMSysconfigExportedConnection *found = NULL;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	for (iter = priv->connections; iter; iter = g_slist_next (iter)) {
		NMSysconfigExportedConnection *item = NM_SYSCONFIG_EXPORTED_CONNECTION (iter->data);
		NMConnection *wrapped;

		wrapped = nm_exported_connection_get_connection (NM_EXPORTED_CONNECTION (item));
		if (wrapped == connection) {
			found = item;
			break;
		}
	}

	if (!found) {
		g_warning ("%s: cannot update unknown connection", __func__);
		return;
	}

	/* If the connection is no longer valid, it gets removed */
	if (!nm_connection_verify (connection)) {
		remove_connection (self, connection);
		return;
	}

	hash = nm_connection_to_hash (connection);
	nm_exported_connection_signal_updated (NM_EXPORTED_CONNECTION (found), hash);
	g_hash_table_destroy (hash);
}

GSList *
nm_sysconfig_settings_get_connections (NMSysconfigSettings *self)
{
	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), NULL);

	return NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self)->connections;
}

void
nm_sysconfig_settings_update_unamanged_devices (NMSysconfigSettings *self,
                                                GSList *new_list)
{
	NMSysconfigSettingsPrivate *priv;
	GSList *iter;

	g_return_if_fail (NM_IS_SYSCONFIG_SETTINGS (self));

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);

	g_hash_table_remove_all (priv->unmanaged_devices);
	for (iter = new_list; iter; iter = g_slist_next (iter)) {
		if (!g_hash_table_lookup (priv->unmanaged_devices, iter->data)) {
			g_hash_table_insert (priv->unmanaged_devices,
			                     g_strdup (iter->data),
			                     GUINT_TO_POINTER (1));
		}
	}
	g_object_notify (G_OBJECT (self), NM_SYSCONFIG_SETTINGS_UNMANAGED_DEVICES);
}

gboolean
nm_sysconfig_settings_is_device_managed (NMSysconfigSettings *self,
                                         const char *udi)
{
	NMSysconfigSettingsPrivate *priv;

	g_return_val_if_fail (NM_IS_SYSCONFIG_SETTINGS (self), FALSE);

	priv = NM_SYSCONFIG_SETTINGS_GET_PRIVATE (self);
	if (g_hash_table_lookup (priv->unmanaged_devices, udi))
		return FALSE;
	return TRUE;
}

