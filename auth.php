<?php
// This file is part of Moodle - https://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <https://www.gnu.org/licenses/>.

/**
 * Authentication class for relogin is defined here.
 *
 * @package     auth_relogin
 * @copyright   2023 Mohammad Farouk <phun.for.physics@gmail.com>
 * @license     https://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');

// For further information about authentication plugins please read
// https://docs.moodle.org/dev/Authentication_plugins.
//
// The base class auth_plugin_base is located at /lib/authlib.php.
// Override functions as needed.

/**
 * Authentication class for relogin.
 */
class auth_plugin_relogin extends auth_plugin_base {

    /**
     * Set the properties of the instance.
     */
    public function __construct() {
        $this->authtype = 'relogin';
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username.
     * @param string $password The password.
     * @return bool Authentication success or failure.
     */
    public function user_login($username, $password) {
        global $CFG, $DB;

        // Validate the login by using the Moodle user table.
        // Remove if a different authentication method is desired.
        $user = $DB->get_record('user', array('username' => $username, 'mnethostid' => $CFG->mnet_localhost_id));

        // User does not exist.
        if (!$user) {
            return false;
        }

        return validate_internal_user_password($user, $password);
    }

    /**
     * Returns true if this authentication plugin can change the user's password.
     *
     * @return bool
     */
    public function can_change_password() {
        return false;
    }

    /**
     * Returns true if this authentication plugin can edit the users'profile.
     *
     * @return bool
     */
    public function can_edit_profile() {
        return false;
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    public function is_internal() {
        return true;
    }

    /**
     * Indicates if password hashes should be stored in local moodle database.
     *
     * @return bool True means password hash stored in user table, false means flag 'not_cached' stored there instead.
     */
    public function prevent_local_passwords() {
        return false;
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from get_userinfo() method.
     *
     * @return bool True means automatically copy data from ext to user table.
     */
    public function is_synchronised_with_external() {
        return false;
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool.
     */
    public function can_reset_password() {
        return false;
    }

    /**
     * Returns true if plugin allows signup and user creation.
     *
     * @return bool
     */
    public function can_signup() {
        return false;
    }

    /**
     * Returns true if plugin allows confirming of new users.
     *
     * @return bool
     */
    public function can_confirm() {
        return false;
    }

    /**
     * Returns whether or not this authentication plugin can be manually set
     * for users, for example, when bulk uploading users.
     *
     * This should be overridden by authentication plugins where setting the
     * authentication method manually is allowed.
     *
     * @return bool
     */
    public function can_be_manually_set() {
        return false;
    }

    /**
     * Hook for overriding behavior of login page.
     * This method is called from login/index.php page for all enabled auth plugins.
     *
     * @global object
     * @global object
     */
    public function loginpage_hook() {
        if (get_config('auth_relogin', 'loginpage')) {
            $this->pre_loginpage_hook();
        }
    }

    /**
     * Hook for overriding behavior before going to the login page.
     *
     * This method is called from require_login from potentially any page for
     * all enabled auth plugins and gives each plugin a chance to redirect
     * directly to an external login page, or to instantly login a user where
     * possible.
     *
     * If an auth plugin implements this hook, it must not rely on ONLY this
     * hook in order to work, as there are many ways a user can browse directly
     * to the standard login page. As a general rule in this case you should
     * also implement the loginpage_hook as well.
     *
     */
    public function pre_loginpage_hook() {
        global $DB, $CFG;
        // Try to automatic login the user by two different ways
        // once by check http_cookies and another by ip address.

        if (isset($_SERVER['HTTP_COOKIE'])) {
            $matches = [];
            // Check the plugin cookies.
            if (isset($_COOKIE['ReLoginMoodle'])) {
                $matches[] = $_COOKIE['ReLoginMoodle'];
                $a = true;
            } else {
                $a = false;
            }
            // Check moodle cookies.
            if (!isset($CFG->sessioncookie)) {
                $sessionname = 'MoodleSession';
            } else {
                $sessionname = 'MoodleSession'.$CFG->sessioncookie;
            }
            if (isset($_COOKIE[$sessionname])) {
                $matches[] = $_COOKIE[$sessionname];
                $b = true;
            } else {
                $b = false;
            }

            if ($a || $b) {
                foreach ($matches as $sid) {
                    $record = $DB->get_record('sessions', ['sid' => $sid]);
                    if (!$record) {
                        continue;
                    }
                    $ruser = \core_user::get_user($record->userid);
                    if ($ruser == false) {
                        continue;
                    }
                    // If the user suspended or deleted, do nothing.
                    if (!empty($ruser->deleted) || !empty($ruser->suspended)) {
                        continue;
                    }
                    // Check if the session is not timed out.
                    $exist = \core\session\manager::session_exists($sid);
                    if (!$exist) {
                        continue;
                    }
                    $found = $ruser;
                    break;
                }
                unset($record, $ruser, $matches);
            }
        }
        // Prepare the events reader.
        $logmanager = get_log_manager();
        $readers = $logmanager->get_readers('core\log\sql_reader');
        $reader = array_pop($readers);
        // If the first method fail try ip address.
        $ip = getremoteaddr(false);
        // Check if the settings enabled.
        $ipsetting = get_config('auth_relogin', 'loginip');
        if (!isset($found) && !empty($ip) && $ipsetting) {
            // Check if this ip used by more than one person?
            // if multiple records exists, we cannot risk logging in the user, may be it will mix with someone else.
            $countips = $DB->count_records('user', ['lastip' => $ip]);
            if ($countips == 1) {
                $records1 = $DB->get_records('sessions', ['lastip' => $ip], 'timecreated DESC');
                $records2 = $DB->get_records('sessions', ['firstip' => $ip], 'timecreated DESC');
                $records = array_merge($records1, $records2);
                foreach ($records as $record) {
                    $sid = $record->sid;
                    // Check if the session is not timed out.
                    $exist = \core\session\manager::session_exists($record->sid);
                    if (!$exist) {
                        continue;
                    }
                    $ruser = \core_user::get_user($record->userid);
                    if ($ruser == false) {
                        continue;
                    }
                    // If the user suspended or deleted, do nothing.
                    if (!empty($ruser->deleted) || !empty($ruser->suspended)) {
                        continue;
                    }
                    // Check that this ip matches this user.
                    // We don't want to login someone instate of some one else.
                    if ($ruser->lastip != $ip) {
                        continue;
                    }
                    // Check all events from the last login of the founded user
                    // if the ip matches with other user
                    // just terminate this method.
                    $ok = true;
                    if ($reader !== null) {
                        $params = array(
                            'time' => $ruser->lastaccess - 60 * 60 * 24 * 7,
                            'ip' => $ip
                        );
                        $where = 'ip = :ip AND timecreated >= :time';
                        $events = $reader->get_events_select($where, $params, 'timecreated DESC', 0, 0);
                        foreach ($events as $e) {
                            if ($e->userid != $ruser->id) {
                                $ok = false;
                                break;
                            }
                        }
                    }
                    if (!$ok) {
                        continue;
                    }
                    $found = $ruser;

                    break;
                }
                unset($records, $records1, $records2, $ruser);
            }
        }
        // We did our best.
        if (!isset($found)) {
            return;
        }

        if ($reader !== null) {
            $params = array(
                'userid' => $found->id,
                'objectid' => $found->id,
                'action' => 'loggedout',
                'target' => 'user',
                'time' => time() - 60 * 60 * 24,
            );
            $where = 'userid = :userid AND objectid = :objectid AND action = :action AND timecreated > :time';
            $loggedout = $reader->get_events_select($where, $params, 'timecreated DESC', 0, 0);
            // Check if the user already logged out in the last 24 hours.
            foreach ($loggedout as $l) {
                if ($l->other['sessionid'] == $sid) {
                    return;
                }
            }
        }
        // Use manual if auth not set.
        $userauth = empty($found->auth) ? 'manual' : $found->auth;
        if ($userauth == 'nologin' || !is_enabled_auth($userauth)) {
            return;
        }
        $auths = get_enabled_auth_plugins();

        foreach ($auths as $auth) {
            $authplugin = get_auth_plugin($auth);
            try {
                $authplugin->sync_roles($found);
                // Some auth plugins don't rely on password in authenticated hook.
                $authplugin->user_authenticated_hook($found, $found->username, '');
            }
        }
        // Finally login the user.
        complete_user_login($found);
    }

    /**
     * Post authentication hook.
     * This method is called from authenticate_user_login() for all enabled auth plugins.
     *
     * @param object $user user object, later used for $USER
     * @param string $username (with system magic quotes)
     * @param string $password plain text password (with system magic quotes)
     */
    public function user_authenticated_hook(&$user, $username, $password) {
        global $CFG, $DB;
        // Check if permanent cookies enabled.
        if (!get_config('auth_relogin', 'cookies')) {
            return;
        }
        // Prepare the cookies parameters according to site settings.
        $cookiesecure = is_moodle_cookie_secure();
        // Set sessioncookie variable if it isn't already.
        if (!isset($CFG->sessioncookie)) {
            $sessionname = 'MoodleSession';
        } else {
            $sessionname = 'MoodleSession'.$CFG->sessioncookie;
        }

        if (isset($_COOKIE[$sessionname])) {
            $sid = $_COOKIE[$sessionname];
        } else {
            $sessions = $DB->get_records('sessions', ['userid' => $user->id], 'timemodified DESC', 'sid', 0, 1);
            if (!empty($sessions)) {
                $first = array_key_first($sessions);
                $sid = $sessions[$first]->sid;
            } else {
                return;
            }
        }

        $options = [
            'expires' => time() + 60 * 60 * 24 * 30,
            'path' => $CFG->sessioncookiepath,
            'domain' => $CFG->sessioncookiedomain,
            'secure' => $cookiesecure,
            'httponly' => $CFG->cookiehttponly,
        ];
        if (\core_useragent::is_chrome() && \core_useragent::check_chrome_version('78') && is_moodle_cookie_secure()) {
            $options['samesite'] = 'None';
        }

        $cookiename = 'ReLoginMoodle';
        unset($_COOKIE[$cookiename]);
        setcookie($cookiename, $sid, $options);
    }

    /**
     * Post logout hook.
     *
     * This method is used after moodle logout by auth classes to execute server logout.
     *
     * @param stdClass $user clone of USER object before the user session was terminated
     */
    public function postlogout_hook($user) {
        global $CFG, $DB;
        // When the user logout normally, making sure this plugin didn't log him again.
        // Also it enhance security.
        // Unset this plugin cookies.
        $cookiename = 'ReLoginMoodle';
        setcookie($cookiename, '', time() - 3600);
        unset($_COOKIE[$cookiename]);
        // Unset normal moodle cookies.
        if (!isset($CFG->sessioncookie)) {
            $sessionname = 'MoodleSession';
        } else {
            $sessionname = 'MoodleSession'.$CFG->sessioncookie;
        }
        unset($_COOKIE[$sessionname]);
        // Delete any remained sessions records for this ip address.
        $DB->delete_records('sessions', ['userid' => $user->id, 'lastip' => getremoteaddr()]);
    }
}
